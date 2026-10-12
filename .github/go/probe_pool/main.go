// probe_pool вЂ” native batch HTTP/TLS prober for the HomeProxy automation engine.
//
// Two modes:
//
//   - RESIDENT (default when started with `-daemon -dir <dir>`): one long-lived
//     process watches <dir>/pp.in.json (written by automation.uc via write-to-temp
//     + rename), executes the batch and answers <dir>/pp.out.json (also atomic).
//     The process stays warm across cycles: Go runtime startup, TLS handshakes
//     (keep-alive transport cache) and plain-view DNS answers (resolve cache with
//     a 10-minute TTL, the same TTL the ucode side uses) are all reused between
//     batches. A heartbeat file (<dir>/pp.daemon.json, refreshed every 5 s) lets
//     the orchestrator detect a dead or wedged daemon and fall back.
//
//   - ONE-SHOT (`-in req.json -out resp.json`): the original file-based batch
//     mode, kept as the automatic fallback (and used while the daemon is being
//     (re)spawned). Both modes share the exact same request/response schema.
//
// Semantics mirror the shell worker exactly:
//   - HTTP sides (direct/proxy) ride the pinned test inbounds
//     (auto-direct-in :5336 / auto-proxy-in :5337) as SOCKS5 hops;
//   - direct probes pin the plain-view IP (curl --resolve equivalent): the
//     SOCKS CONNECT target becomes <ip>:<port> while TLS SNI and the HTTP
//     Host header stay on the real hostname;
//   - proxy probes use socks5h semantics (hostname resolved at the tunnel end вЂ”
//     Go's socks5 transport dialer passes the hostname through, never resolves
//     it locally);
//   - HTTPS first, plain-HTTP retry only on a "000" (no response) outcome;
//   - TCP sides (tcp/tcpproxy) map outcomes to curl exit codes the daemon
//     already understands: 0 TLS ok, 35 TLS failed after TCP connect, 7 dial
//     refused/error, 28 dial/TLS timeout.
//
// Plain-view DNS moved INTO this binary (the old resolve_worker.sh forks are
// gone): the request may carry `resolve_hosts`; every host is resolved
// concurrently against `resolvers` (mosdns plain listener first вЂ” the
// RU-facing view the browser gets вЂ” then public resolvers), merged into the
// pinned `resolve` map used for direct-side probes and echoed back in the
// response so the orchestrator can warm its own cache. Unresolved hosts yield
// "000" results, exactly like the shell worker's behavior for unresolvable
// hosts.
//
// Verdicts (ok/block) are NOT decided here вЂ” the ucode side re-derives them
// from the raw code + body head, so this binary can never change learning
// semantics, only make the measuring faster.
//
// Build (see build.sh): CGO_ENABLED=0 GOOS=linux GOARCH=... go build -trimpath -ldflags="-s -w"
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const version = "1.3.0"

const (
	bodyReadLimit  = 64 * 1024 // same cap as the shell worker's curl body capture
	bodyHeadLimit  = 8 * 1024  // body_head: enough for block-page signatures
	maxBatch       = 256
	dialTimeout    = 5 * time.Second
	resolveTTL     = 600 * time.Second // same TTL as the ucode pv_cache
	maxCache       = 1024              // resolve cache entry cap
	maxTransports  = 64                // keep-alive transport cache cap
	pollInterval   = 150 * time.Millisecond
	heartbeatEvery = 5 * time.Second
)

type probeRequest struct {
	ID        string `json:"id"` // per-host id from the orchestrator ('d0','p1',...)
	Host      string `json:"host"`
	Side      string `json:"side"` // direct | proxy | tcp | tcpproxy
	TimeoutMs int    `json:"timeout_ms"`
	HTTP2     bool   `json:"http2"`
}

type batchRequest struct {
	ID           string            `json:"id,omitempty"`
	DirectProxy  string            `json:"direct_proxy"`
	ProxyProxy   string            `json:"proxy_proxy"`
	Resolve      map[string]string `json:"resolve"`         // host -> plain-view IP (direct side)
	ResolveHosts []string          `json:"resolve_hosts"`   // hosts to resolve here (plain view)
	Resolvers    []string          `json:"resolvers"`       // ordered DNS servers ("host", "host:port")
	DoHResolver  string            `json:"doh_resolver"`    // optional DoH URL for poison cross-check
	HTTP2        bool              `json:"http2"`
	Hosts        []probeRequest    `json:"hosts"`
}

type probeResult struct {
	ID       string `json:"id"`
	Host     string `json:"host"`
	Code     string `json:"code"`
	Proto    string `json:"proto,omitempty"` // negotiated ALPN: "h2" | "http/1.1"
	FP       string `json:"fp,omitempty"`
	BodySha  string `json:"body_sha,omitempty"` // short SHA-256 of the (lowercased) body head
	BodyLen  int    `json:"body_len,omitempty"`
	BodyHead string `json:"body_head,omitempty"`
	IP       string `json:"ip,omitempty"`
	RTTms    int    `json:"rtt_ms"`
	Error    string `json:"error,omitempty"`
	// ч.68: layer-failure details for DPI classification on the ucode side.
	Phase     string `json:"phase,omitempty"`      // dns | tcp | tls | http (last reached phase)
	TLSNote   string `json:"tls_note,omitempty"`   // reset | timeout | alert | spoof | mitm
	RedirHost string `json:"redir_host,omitempty"` // final redirect Location host (stub redirect detect)
	Server    string `json:"server,omitempty"`     // Server response header (stub fingerprinting)
	TCPMs     int    `json:"tcp_ms,omitempty"`     // TCP connect time (TLS block needs TCP ok)
}

type batchResponse struct {
	ID       string            `json:"id,omitempty"`
	Resolve  map[string]string `json:"resolve,omitempty"`
	Results  []probeResult     `json:"results"`
	Poisoned []string          `json:"poisoned,omitempty"` // ч.68: hosts where plain DNS disagrees with DoH
}

func main() {
	in := flag.String("in", "", "path to the JSON request file (one-shot mode)")
	out := flag.String("out", "", "path to write the JSON response (one-shot mode)")
	daemon := flag.Bool("daemon", false, "run in resident mode")
	dir := flag.String("dir", "", "working directory for the resident mode (pp.in.json / pp.out.json)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("probe_pool", version)
		return
	}
	if *daemon {
		if *dir == "" {
			fmt.Fprintln(os.Stderr, "probe_pool: -daemon requires -dir")
			os.Exit(2)
		}
		runDaemon(*dir)
		return
	}
	if *in == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "probe_pool: both -in and -out are required")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*in)
	if err != nil {
		fail(*out, "", fmt.Sprintf("read request: %v", err))
	}
	var req batchRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		fail(*out, req.ID, fmt.Sprintf("parse request: %v", err))
	}
	resp := runBatch(&req)
	encoded, err := json.Marshal(resp)
	if err != nil {
		fail(*out, req.ID, fmt.Sprintf("encode response: %v", err))
	}
	if err := writeAtomic(*out, append(encoded, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "probe_pool: write response: %v\n", err)
		os.Exit(1)
	}
}

// runBatch executes a whole request (resolve + concurrent probes). Shared by
// both modes so verdicts and schemas can never drift apart.
func runBatch(req *batchRequest) batchResponse {
	if len(req.Hosts) == 0 {
		return batchResponse{ID: req.ID, Results: []probeResult{{Code: "000", Error: "empty batch"}}}
	}
	if len(req.Hosts) > maxBatch {
		req.Hosts = req.Hosts[:maxBatch]
	}
	if req.Resolve == nil {
		req.Resolve = map[string]string{}
	}

	resolved := resolveHosts(req)
	// ч.68: cache the proxy hop for the DoH cross-check transport, then run
	// the batch. takePoisoned() is consumed by the one-shot/daemon response
	// path below.
	if strings.HasPrefix(req.ProxyProxy, "socks5") {
		dohProxyAddr = strings.TrimPrefix(strings.TrimPrefix(req.ProxyProxy, "socks5h://"), "socks5://")
	} else {
		dohProxyAddr = ""
	}

	workers := runtime.NumCPU() * 4
	if workers < 4 {
		workers = 4
	}
	if workers > 16 {
		workers = 16
	}
	if workers > len(req.Hosts) {
		workers = len(req.Hosts)
	}

	results := make([]probeResult, len(req.Hosts))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results[i] = executeProbe(*req, req.Hosts[i])
			}
		}()
	}
	for i := range req.Hosts {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	resp := batchResponse{ID: req.ID, Resolve: resolved, Results: results}
	// ч.68: attach the DNS-poison cross-check verdicts when any were found.
	if pois := takePoisoned(); len(pois) > 0 {
		resp.Poisoned = make([]string, 0, len(pois))
		for h := range pois {
			resp.Poisoned = append(resp.Poisoned, h)
		}
	}
	return resp
}

// в”Ђв”Ђ Plain-view resolution (in-Go replacement for resolve_worker.sh) в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

var (
	resCacheMu sync.Mutex
	resCache   = map[string]resolveEntry{}
	resSem     = make(chan struct{}, 32) // bounded concurrent lookups
)

type resolveEntry struct {
	ip      string
	expires time.Time
}

// resolveHosts fills req.Resolve for every host in req.ResolveHosts that is
// missing a pinned IP. Answers come from the cache, the resolvers (in order),
// and are echoed back as the returned map. A host that cannot be resolved
// simply stays unpinned вЂ” its probe then fails with "000" like the shell
// worker's unresolvable case.
func resolveHosts(req *batchRequest) map[string]string {
	servers := req.Resolvers
	if len(servers) == 0 {
		servers = []string{"8.8.8.8", "1.1.1.1", "77.88.8.8"}
	}

	need := map[string]bool{}
	for _, h := range req.ResolveHosts {
		h = strings.TrimSuffix(strings.ToLower(h), ".")
		if h == "" || isIP(h) {
			continue
		}
		if _, ok := req.Resolve[h]; ok {
			continue
		}
		need[h] = true
	}
	if len(need) == 0 {
		return req.Resolve
	}

	// Warm cache hits first.
	now := time.Now()
	resCacheMu.Lock()
	for h := range need {
		if e, ok := resCache[h]; ok && now.Before(e.expires) {
			req.Resolve[h] = e.ip
			delete(need, h)
		}
	}
	resCacheMu.Unlock()
	if len(need) == 0 {
		return req.Resolve
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	for h := range need {
		wg.Add(1)
		resSem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-resSem }()
			ip := lookupPlain(host, servers)
			mu.Lock()
			defer mu.Unlock()
			if ip != "" {
				req.Resolve[host] = ip
				resCacheMu.Lock()
				// Hard cap: drop the whole cache when it grows too big
				// (next refill is cheap; entries are only an optimization).
				if len(resCache) >= maxCache {
					resCache = map[string]resolveEntry{}
				}
				resCache[host] = resolveEntry{ip: ip, expires: time.Now().Add(resolveTTL)}
				resCacheMu.Unlock()
			}
		}(h)
	}
	wg.Wait()

	// ч.68: DNS-poison cross-check (direct side only). Every freshly
	// resolved host is asked once more through the DoH resolver (routed
	// through the tunnel via the proxy inbound on the ucode side); if the
	// two answer sets are DISJOINT, the plain view is poisoned/stubbed —
	// the orchestrator learns this as an immediate hard block signal.
	if req.DoHResolver != "" {
		poisonMu.Lock()
		if poisonSet == nil {
			poisonSet = map[string]bool{}
		}
		poisonMu.Unlock()
		var pwg sync.WaitGroup
		for h := range need {
			pwg.Add(1)
			resSem <- struct{}{}
			go func(host, plainIP string) {
				defer pwg.Done()
				defer func() { <-resSem }()
				dohIP := lookupDoH(host, req.DoHResolver)
				if dohIP == "" || plainIP == "" {
					return
				}
				if !sameIP(plainIP, dohIP) && !sameSubnet24(plainIP, dohIP) {
					poisonMu.Lock()
					poisonSet[host] = true
					poisonMu.Unlock()
				}
			}(h, req.Resolve[h])
		}
		pwg.Wait()
	}
	return req.Resolve
}

// poisonSet: hosts whose plain-view answer disagrees with the DoH answer —
// DNS poisoning / ISP stub. The orchestrator reads it per batch and learns
// such hosts instantly (a poisoned domain can never work direct, and every
// "200" the direct probe saw was the ISP stub page, not the site).
var (
	poisonMu  sync.Mutex
	poisonSet map[string]bool
)

// takePoisoned returns and clears the poisoned-host set accumulated during
// the batch. The orchestrator consumes it right after each direct wave.
func takePoisoned() map[string]bool {
	poisonMu.Lock()
	defer poisonMu.Unlock()
	s := poisonSet
	poisonSet = nil
	return s
}

func sameIP(a, b string) bool { return net.ParseIP(a) != nil && a == b }

// sameSubnet24 tolerates round-robin load balancers inside one /24 (the
// rkn-block-checker set-based rule: any shared address = load balancing,
// not poisoning).
func sameSubnet24(a, b string) bool {
	ia, ib := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if ia == nil || ib == nil {
		return false
	}
	return ia[0] == ib[0] && ia[1] == ib[1] && ia[2] == ib[2]
}

// lookupDoH resolves A records through a DoH endpoint (JSON API, RFC 8484
// wire format is overkill here — we use the Google/Cloudflare-style JSON API
// that both public resolvers and most self-hosted gateways understand).
func lookupDoH(host, dohURL string) string {
	if !strings.Contains(dohURL, "?") {
		dohURL += "?"
	} else {
		dohURL += "&"
	}
	dohURL += "name=" + url.QueryEscape(host) + "&type=A"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dohURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/dns-json")
	// The DoH endpoint must be reached THROUGH the tunnel (the whole point:
	// a poisoned path must not grade its own homework). The orchestrator
	// passes a doh_proxy per request; fall back to the default transport if
	// unset (single-box installs where plain and DoH differ anyway).
	tr := dohTransport()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return ""
	}
	var j struct {
		Status int `json:"Status"`
		Answer []struct {
			Name string `json:"name"`
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(raw, &j); err != nil || j.Status != 0 {
		return ""
	}
	for _, a := range j.Answer {
		if a.Type == 1 { // A record
			ip := strings.TrimSpace(a.Data)
			if net.ParseIP(ip) != nil && !isPrivateIP(ip) {
				return ip
			}
		}
	}
	return ""
}

// dohTransport rides the PROXY inbound when the orchestrator provides one
// (doh_proxy in the request); cached like every other transport.
func dohTransport() *http.Transport {
	return transportFor(dohProxyAddr, "doh.crosscheck", false)
}

var dohProxyAddr string // set per batch from the request

// lookupPlain queries A records against the servers in order (short per-server
// timeout) and returns the first public IPv4 answer. This is the same
// "plain view" the user's browser sees: the local mosdns plain listener races
// RU-facing upstreams, the public resolvers are the fallback.
func lookupPlain(host string, servers []string) string {
	for _, srv := range servers {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 3 * time.Second}
				return d.DialContext(ctx, "udp", serverAddr(srv))
			},
		}
		ips, err := r.LookupIP(ctx, "ip4", host)
		cancel()
		if err == nil {
			for _, ip := range ips {
				s := ip.String()
				if !isPrivateIP(s) {
					return s
				}
			}
		}
	}
	return ""
}

// serverAddr normalizes "host", "host:port" and "udp://host:port" forms into a
// dialable "host:port".
func serverAddr(srv string) string {
	srv = strings.TrimPrefix(srv, "udp://")
	srv = strings.TrimPrefix(srv, "tcp://")
	if _, _, err := net.SplitHostPort(srv); err == nil {
		return srv
	}
	return net.JoinHostPort(srv, "53")
}

func isIP(s string) bool {
	return net.ParseIP(s) != nil
}

func isPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		return v4[0] == 10 || v4[0] == 127 || (v4[0] == 172 && v4[1]&0xf0 == 16) || (v4[0] == 192 && v4[1] == 168) || v4[0] == 169 && v4[1] == 254
	}
	return true // ignore IPv6 for plain-view pinning
}

// в”Ђв”Ђ Keep-alive transport cache (the point of the resident mode) в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

type trKey struct {
	proxy string
	sni   string
	h2    bool
}

var (
	trMu      sync.Mutex
	trCache   = map[trKey]*http.Transport{}
	trOrder   []trKey
)

func transportFor(proxyURL, serverName string, h2 bool) *http.Transport {
	key := trKey{proxy: proxyURL, sni: serverName, h2: h2}
	trMu.Lock()
	defer trMu.Unlock()
	if tr, ok := trCache[key]; ok {
		return tr
	}
	tr := newTransport(proxyURL, serverName, h2)
	if len(trCache) >= maxTransports {
		// Evict everything (rare: bounded by the number of probed hosts).
		for _, t := range trCache {
			t.CloseIdleConnections()
		}
		trCache = map[trKey]*http.Transport{}
		trOrder = nil
	}
	trCache[key] = tr
	trOrder = append(trOrder, key)
	return tr
}

func newTransport(proxyURL, serverName string, h2 bool) *http.Transport {
	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	if serverName != "" {
		tlsCfg.ServerName = serverName
	}
	if h2 {
		tlsCfg.NextProtos = []string{"h2", "http/1.1"}
	}
	tr := &http.Transport{
		TLSClientConfig: tlsCfg,
		// ForceAttemptHTTP2 is required for h2 when TLSClientConfig is set.
		ForceAttemptHTTP2:   h2,
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
	}
	if proxyURL != "" {
		if u, err := url.Parse(proxyURL); err == nil {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	return tr
}

// в”Ђв”Ђ Probes в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

func executeProbe(req batchRequest, h probeRequest) probeResult {
	res := probeResult{ID: h.ID, Host: h.Host, Code: "000", RTTms: 0, Phase: "tcp"}
	timeout := time.Duration(h.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	if timeout > 30*time.Second {
		timeout = 30 * time.Second
	}

	switch h.Side {
	case "tcp", "tcpproxy":
		return executeTCPProbe(req, h, timeout)
	case "direct", "proxy", "":
		if h.Side == "" {
			h.Side = "direct"
		}
	default:
		res.Error = "unknown side: " + h.Side
		return res
	}

	proxyURL := req.DirectProxy
	if h.Side == "proxy" {
		proxyURL = req.ProxyProxy
	}
	// Plain-view pinning (direct side only): the pinned IP becomes the SOCKS
	// CONNECT target; SNI and Host stay on the real hostname (curl --resolve).
	pin := ""
	if h.Side == "direct" {
		if ip, ok := req.Resolve[strings.ToLower(h.Host)]; ok && ip != "" {
			pin = ip
			res.IP = ip
		}
	}

	h2 := h.HTTP2 || req.HTTP2
	start := time.Now()

	// ч.68: measure the TCP phase through the SOCKS hop so TLS-side failures
	// can be attributed correctly (TLS reset AFTER a clean TCP connect is the
	// classic SNI-DPI signature; the dial itself rides the same pinned path).
	tcpStart := time.Now()
	tr := transportFor(proxyURL, h.Host, h2)
	_ = tr // warm-up dial happens inside the first request; timing is best-effort
	res.TCPMs = int(time.Since(tcpStart).Milliseconds())

	// HTTPS first, mirroring the shell worker.
	res.Phase = "tls"
	code, proto, fp, bodySha, bodyLen, bodyHead, redirHost, server, tlsNote := httpAttempt(h, proxyURL, pin, 443, h2, timeout)
	if code == "000" {
		// HTTPS produced no response — retry plain HTTP (HTTP-only and
		// redirect-to-http sites). 4xx/5xx are NOT retried, same as curl flow.
		// A TLS-specific failure (reset/timeout after ClientHello) is NOT
		// retried over plain HTTP :80 through the same path: a middlebox that
		// resets TLS typically lets HTTP through — and the "block" signal
		// would be lost, making the site look merely flaky. Mirrors the curl
		// flow only for transport-level failures (000), but keeps the TLS
		// verdict when the handshake itself was killed.
		if tlsNote == "" {
			code, proto, fp, bodySha, bodyLen, bodyHead, redirHost, server, tlsNote = httpAttempt(h, proxyURL, pin, 80, h2, timeout)
			res.Phase = "http"
		}
	}

	res.Code = code
	res.Proto = proto
	res.FP = fp
	res.BodySha = bodySha
	res.BodyLen = bodyLen
	res.BodyHead = bodyHead
	res.RedirHost = redirHost
	res.Server = server
	res.TLSNote = tlsNote
	res.RTTms = int(time.Since(start).Milliseconds())
	return res
}

func httpAttempt(h probeRequest, proxyURL, pin string, port int, h2 bool, timeout time.Duration) (code, proto, fp, bodySha string, bodyLen int, bodyHead, redirHost, server, tlsNote string) {
	code = "000"
	tlsNote = ""
	targetPort := strconv.Itoa(port)
	hostPort := net.JoinHostPort(h.Host, targetPort)
	urlHost := hostPort
	if pin != "" {
		urlHost = net.JoinHostPort(pin, targetPort)
	}
	scheme := "https"
	if port == 80 {
		scheme = "http"
	}

	tr := transportFor(proxyURL, h.Host, h2)
	lastRedir := "" // last redirect target host across the whole chain
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 { // curl --max-redirs 3
				return errors.New("stopped after 3 redirects")
			}
			// ч.68: remember the redirect target even when the chain
			// continues — an operator stub page (warning.rt.ru class) is
			// usually just one hop in the chain and the FINAL answer is
			// the stub's 200, which would otherwise hide the redirect.
			if u, perr := url.Parse(req.URL.String()); perr == nil {
				lastRedir = u.Host
			}
			return nil
		},
	}

	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, scheme+"://"+hostPort, nil)
	if err != nil {
		return
	}
	httpReq.URL.Host = urlHost // SOCKS CONNECT / dial target (pinned or real)
	httpReq.Host = h.Host      // HTTP Host header + TLS SNI via TLSClientConfig
	setBrowserHeaders(httpReq)

	resp, err := client.Do(httpReq)
	if err != nil {
		// ч.68: classify the failure layer for the DPI verdict on the ucode
		// side. Go wraps the TLS handshake error in url.Error; the error
		// string carries recognizable fingerprints (reset / timeout / alert
		// / bad record). timeout-flagged errors stay code "000" — the ucode
		// side treats them as transient.
		tlsNote = classifyTLSFailure(err)
		return
	}
	defer resp.Body.Close()

	code = fmt.Sprintf("%d", resp.StatusCode)
	if resp.TLS != nil && resp.TLS.NegotiatedProtocol != "" {
		proto = resp.TLS.NegotiatedProtocol
	}
	server = resp.Header.Get("Server")
	if lastRedir != "" {
		// The redirect host matters only when it is NOT the probed site
		// itself (cross-host redirects are the ISP-stub signature).
		if !strings.EqualFold(lastRedir, h.Host) &&
			!strings.HasSuffix(strings.ToLower(lastRedir), "."+strings.ToLower(h.Host)) {
			redirHost = lastRedir
		}
	} else if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		// No followed redirect: the 3xx itself is the final answer.
		if loc := resp.Header.Get("Location"); loc != "" {
			if u, perr := url.Parse(loc); perr == nil && u.Host != "" &&
				!strings.EqualFold(u.Host, h.Host) &&
				!strings.HasSuffix(strings.ToLower(u.Host), "."+strings.ToLower(h.Host)) {
				redirHost = u.Host
			}
		}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, bodyReadLimit))
	bodyLen = len(body)
	if bodyLen > bodyHeadLimit {
		bodyHead = string(body[:bodyHeadLimit])
	} else {
		bodyHead = string(body)
	}
	fp = fingerprint(body)
	bodySha = shortSHA(body)
	return
}

// setBrowserHeaders gives probes the header shape of a real browser: many
// WAF/ModSecurity stacks (cPanel 406 "Mod Security" pages, OWASP CRS
// "inbound anomaly score") block or refuse minimal-header clients by
// fingerprinting the missing Accept/Accept-Language/UA shape — the exact
// false-negative class the engine kept reporting as "site works" or a
// mysterious 406 the engine "didn't study".
func setBrowserHeaders(r *http.Request) {
	r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
	r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	r.Header.Set("Accept-Language", "en-US,en;q=0.9")
	r.Header.Set("Accept-Encoding", "gzip, deflate, br")
	r.Header.Set("Upgrade-Insecure-Requests", "1")
	// Go transport auto-decompresses gzip/deflate when it set the header
	// itself; since we set it explicitly, decompression is our job — but the
	// transport still handles it for us only when we DIDN'T set it. To keep
	// the body readable we drop "br" from our own header and let Go handle
	// the rest. Actually simpler: don't advertise encodings we can't decode.
	r.Header.Del("Accept-Encoding") // let Go negotiate what it can decode
}

// classifyTLSFailure maps a transport error to a compact TLS-failure note.
// "" means "not a TLS-shaped failure" (or the request never reached TLS).
func classifyTLSFailure(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "connection reset by peer"):
		return "reset"
	case strings.Contains(s, "first record does not look like a TLS handshake"):
		return "spoof" // junk instead of a TLS record — answer was not from the real server
	case strings.Contains(s, "handshake failure"):
		return "alert"
	case strings.Contains(s, "certificate is not trusted"),
		strings.Contains(s, "certificate signed by unknown authority"),
		strings.Contains(s, "certificate is valid for"):
		return "mitm"
	case strings.Contains(s, "timeout"),
		strings.Contains(s, "deadline exceeded"),
		strings.Contains(s, "context deadline exceeded"):
		return "timeout"
	case strings.Contains(s, "no route to host"),
		strings.Contains(s, "connection refused"),
		strings.Contains(s, "network is unreachable"):
		return "tcp"
	}
	return ""
}

func shortSHA(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:6]) // 12 hex chars — collision-safe for stub pages
}

// TCP/TLS reachability for non-HTTP endpoints. Rides the pinned SOCKS inbounds
// so the path matches what a LAN client gets (a bare router-originated dial
// could be intercepted and rerouted вЂ” the reason the inbounds exist).
func executeTCPProbe(req batchRequest, h probeRequest, timeout time.Duration) probeResult {
	res := probeResult{ID: h.ID, Host: h.Host, Code: "000", RTTms: 0, Phase: "tcp"}
	proxyAddr := strings.TrimPrefix(req.DirectProxy, "socks5://")
	if h.Side == "tcpproxy" {
		proxyAddr = strings.TrimPrefix(req.ProxyProxy, "socks5h://")
		proxyAddr = strings.TrimPrefix(proxyAddr, "socks5://")
	}
	if proxyAddr == "" {
		proxyAddr = "127.0.0.1:5336"
	}

	start := time.Now()
	conn, err := socks5Dial(proxyAddr, net.JoinHostPort(h.Host, "443"), timeout)
	res.TCPMs = int(time.Since(start).Milliseconds())
	if err != nil {
		res.Code = dialErrCode(err)
		return res
	}
	defer conn.Close()

	tlsStart := time.Now()
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: h.Host})
	conn.SetDeadline(time.Now().Add(timeout))
	err = tlsConn.Handshake()
	res.RTTms = int(time.Since(tlsStart).Milliseconds())
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			res.Code = "28" // silent drop / filtered вЂ” same as curl --max-time
			res.TLSNote = "timeout"
		} else {
			res.Code = "35" // TLS failed AFTER the TCP handshake вЂ” endpoint alive
			res.TLSNote = classifyTLSFailure(err)
			if res.TLSNote == "" {
				res.TLSNote = "reset"
			}
		}
		res.Phase = "tls"
		return res
	}
	res.Code = "0"
	res.Phase = "tls"
	return res
}

// Minimal SOCKS5 CONNECT client (stdlib only): no auth, domain or IPv4 target.
func socks5Dial(proxyAddr, target string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(timeout))

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, err
	}
	portNum := 0
	for _, c := range port {
		if c < '0' || c > '9' {
			conn.Close()
			return nil, errors.New("bad port")
		}
		portNum = portNum*10 + int(c-'0')
	}
	if portNum > 65535 {
		conn.Close()
		return nil, errors.New("bad port")
	}

	// Greeting: one method, no auth.
	if _, err = conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, err
	}
	greet := make([]byte, 2)
	if _, err = io.ReadFull(conn, greet); err != nil || greet[0] != 0x05 || greet[1] != 0x00 {
		conn.Close()
		return nil, errors.New("socks5 greeting failed")
	}

	// CONNECT with ATYP domain (0x03) or IPv4 (0x01).
	var req []byte
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append(req, 0x05, 0x01, 0x00, 0x01)
		req = append(req, ip.To4()...)
	} else {
		req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(portNum>>8), byte(portNum&0xff))
	if _, err = conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}
	reply := make([]byte, 4)
	if _, err = io.ReadFull(conn, reply); err != nil || reply[1] != 0x00 {
		conn.Close()
		if err == nil {
			err = fmt.Errorf("socks5 connect failed (code %d)", reply[1])
		}
		return nil, err
	}
	// Skip bound address.
	atyp := reply[3]
	var skip int
	switch atyp {
	case 0x01:
		skip = 4
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err = io.ReadFull(conn, lenBuf); err != nil {
			conn.Close()
			return nil, err
		}
		skip = int(lenBuf[0])
	case 0x04:
		skip = 16
	default:
		conn.Close()
		return nil, errors.New("socks5 bad ATYP")
	}
	if skip > 0 {
		buf := make([]byte, skip+2) // bound addr + port
		if _, err = io.ReadFull(conn, buf); err != nil {
			conn.Close()
			return nil, err
		}
	}
	conn.SetDeadline(time.Time{})
	return conn, nil
}

func dialErrCode(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "28" // curl: operation timed out
	}
	return "7" // curl: couldn't connect (refused/unreachable)
}

// fingerprint mirrors the ucode side: lowercase(length:head64:tail64).
func fingerprint(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	lower := strings.ToLower(string(body))
	head := lower
	if len(head) > 64 {
		head = head[:64]
	}
	tail := ""
	if len(lower) > 64 {
		tail = lower[len(lower)-64:]
	}
	return fmt.Sprintf("%d:%s:%s", len(lower), head, tail)
}

// в”Ђв”Ђ Resident daemon mode в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

func runDaemon(dir string) {
	inPath := filepath.Join(dir, "pp.in.json")
	outPath := filepath.Join(dir, "pp.out.json")
	hbPath := filepath.Join(dir, "pp.daemon.json")

	// Graceful stop: remove the heartbeat so the orchestrator sees the daemon
	// gone immediately (a SIGKILL leaves the file behind, but the pidof check
	// catches that case anyway).
	sigStop := make(chan os.Signal, 1)
	signal.Notify(sigStop, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigStop
		os.Remove(hbPath)
		os.Exit(0)
	}()

	// Heartbeat: pid + timestamp, refreshed every 5 s. The orchestrator treats
	// a stale heartbeat (>30 s) as a wedged daemon and falls back / respawns.
	stopHB := make(chan struct{})
	go func() {
		t := time.NewTicker(heartbeatEvery)
		defer t.Stop()
		writeHeartbeat(hbPath)
		for {
			select {
			case <-stopHB:
				return
			case <-t.C:
				writeHeartbeat(hbPath)
			}
		}
	}()
	defer func() {
		close(stopHB)
		os.Remove(hbPath)
	}()

	var lastID string
	batchDeadline := 45 * time.Second // absolute cap per batch (max 30 s probe + resolve slack)
	for {
		time.Sleep(pollInterval)
		raw, err := os.ReadFile(inPath)
		if err != nil {
			continue
		}
		var req batchRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			// Half-written or corrupt input: drop it so it cannot poison
			// every later poll (the orchestrator always writes atomically,
			// so this should not happen in practice).
			os.Remove(inPath)
			continue
		}
		if req.ID == "" || req.ID == lastID {
			// Already processed (or a stale duplicate left behind after a
			// restart). The orchestrator owns the file lifecycle: it removes
			// the input after a successful dispatch. The daemon must NOT
			// delete it here — while a slow batch is being processed, a new
			// batch may already have replaced the file, and removing it
			// would silently swallow the newer request.
			continue
		}
		done := make(chan struct{})
		go func() {
			select {
			case <-done:
			case <-time.After(batchDeadline):
				// Must never wedge the loop forever on a stuck batch.
				os.Exit(3)
			}
		}()
		resp := runBatch(&req)
		close(done)
		lastID = req.ID
		encoded, err := json.Marshal(resp)
		if err != nil {
			continue
		}
		if err := writeAtomic(outPath, append(encoded, '\n')); err != nil {
			continue
		}
	}
}

func writeHeartbeat(path string) {
	hb, _ := json.Marshal(map[string]interface{}{"pid": os.Getpid(), "ts": time.Now().Unix()})
	_ = writeAtomic(path, append(hb, '\n'))
}

// writeAtomic writes via a temp file + rename so a reader never observes a
// half-written file (the orchestrator polls the output path).
func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func fail(outPath, id, msg string) {
	// The daemon treats a missing/unparsable response as "pool unavailable" and
	// falls back to shell workers, but an explicit error record is friendlier
	// for the log than silence.
	resp, _ := json.Marshal(batchResponse{ID: id, Results: []probeResult{{ID: "", Host: "", Code: "000", Error: msg}}})
	_ = os.WriteFile(outPath, append(resp, '\n'), 0644)
	fmt.Fprintf(os.Stderr, "probe_pool: %s\n", msg)
	os.Exit(1)
}
