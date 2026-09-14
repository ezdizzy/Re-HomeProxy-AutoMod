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
	"crypto/tls"
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

const version = "1.2.0"

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
	ID        string `json:"id"`
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
	HTTP2        bool              `json:"http2"`
	Hosts        []probeRequest    `json:"hosts"`
}

type probeResult struct {
	ID       string `json:"id"`
	Host     string `json:"host"`
	Code     string `json:"code"`
	Proto    string `json:"proto,omitempty"` // negotiated ALPN: "h2" | "http/1.1"
	FP       string `json:"fp,omitempty"`
	BodyLen  int    `json:"body_len,omitempty"`
	BodyHead string `json:"body_head,omitempty"`
	IP       string `json:"ip,omitempty"`
	RTTms    int    `json:"rtt_ms"`
	Error    string `json:"error,omitempty"`
}

type batchResponse struct {
	ID      string            `json:"id,omitempty"`
	Resolve map[string]string `json:"resolve,omitempty"`
	Results []probeResult     `json:"results"`
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

	return batchResponse{ID: req.ID, Resolve: resolved, Results: results}
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
	return req.Resolve
}

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
	res := probeResult{ID: h.ID, Host: h.Host, Code: "000", RTTms: 0}
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

	// HTTPS first, mirroring the shell worker.
	code, proto, fp, bodyLen, bodyHead := httpAttempt(h, proxyURL, pin, 443, h2, timeout)
	if code == "000" {
		// HTTPS produced no response вЂ” retry plain HTTP (HTTP-only and
		// redirect-to-http sites). 4xx/5xx are NOT retried, same as curl flow.
		code, proto, fp, bodyLen, bodyHead = httpAttempt(h, proxyURL, pin, 80, h2, timeout)
	}

	res.Code = code
	res.Proto = proto
	res.FP = fp
	res.BodyLen = bodyLen
	res.BodyHead = bodyHead
	res.RTTms = int(time.Since(start).Milliseconds())
	return res
}

func httpAttempt(h probeRequest, proxyURL, pin string, port int, h2 bool, timeout time.Duration) (code, proto, fp string, bodyLen int, bodyHead string) {
	code = "000"
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
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 { // curl --max-redirs 3
				return errors.New("stopped after 3 redirects")
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
	httpReq.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) probe_pool/"+version)

	resp, err := client.Do(httpReq)
	if err != nil {
		return // code stays "000"
	}
	defer resp.Body.Close()

	code = fmt.Sprintf("%d", resp.StatusCode)
	if resp.TLS != nil && resp.TLS.NegotiatedProtocol != "" {
		proto = resp.TLS.NegotiatedProtocol
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, bodyReadLimit))
	bodyLen = len(body)
	if bodyLen > bodyHeadLimit {
		bodyHead = string(body[:bodyHeadLimit])
	} else {
		bodyHead = string(body)
	}
	fp = fingerprint(body)
	return
}

// TCP/TLS reachability for non-HTTP endpoints. Rides the pinned SOCKS inbounds
// so the path matches what a LAN client gets (a bare router-originated dial
// could be intercepted and rerouted вЂ” the reason the inbounds exist).
func executeTCPProbe(req batchRequest, h probeRequest, timeout time.Duration) probeResult {
	res := probeResult{ID: h.ID, Host: h.Host, Code: "000", RTTms: 0}
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
	res.RTTms = int(time.Since(start).Milliseconds())
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
		} else {
			res.Code = "35" // TLS failed AFTER the TCP handshake вЂ” endpoint alive
		}
		return res
	}
	res.Code = "0"
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
