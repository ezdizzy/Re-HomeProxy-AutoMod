// probe_pool вЂ” native batch HTTP/TLS prober for the HomeProxy automation engine.
//
// One-shot mode only (no daemon, no socket): automation.uc writes a JSON request
// file, runs `probe_pool -in req.json -out resp.json`, reads the JSON response.
// Per batch it probes all hosts CONCURRENTLY with dedicated transports вЂ” the
// equivalent of N parallel curl runs without the N x (fork + nslookup + curl)
// overhead, with HTTP/2 where negotiated.
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
	"runtime"
	"strings"
	"sync"
	"time"
)

const version = "1.1.0"

const (
	bodyReadLimit = 64 * 1024 // same cap as the shell worker's curl body capture
	bodyHeadLimit = 8 * 1024  // body_head: enough for block-page signatures
	maxBatch      = 256
	dialTimeout   = 5 * time.Second
)

type probeRequest struct {
	ID        string `json:"id"`
	Host      string `json:"host"`
	Side      string `json:"side"` // direct | proxy | tcp | tcpproxy
	TimeoutMs int    `json:"timeout_ms"`
	HTTP2     bool   `json:"http2"`
}

type batchRequest struct {
	DirectProxy string            `json:"direct_proxy"`
	ProxyProxy  string            `json:"proxy_proxy"`
	Resolve     map[string]string `json:"resolve"` // host -> plain-view IP (direct side)
	HTTP2       bool              `json:"http2"`
	Hosts       []probeRequest    `json:"hosts"`
}

type probeResult struct {
	ID       string `json:"id"`
	Host     string `json:"host"`
	Code     string `json:"code"`
	FP       string `json:"fp,omitempty"`
	BodyLen  int    `json:"body_len,omitempty"`
	BodyHead string `json:"body_head,omitempty"`
	IP       string `json:"ip,omitempty"`
	RTTms    int    `json:"rtt_ms"`
	Error    string `json:"error,omitempty"`
}

type batchResponse struct {
	Results []probeResult `json:"results"`
}

func main() {
	in := flag.String("in", "", "path to the JSON request file (required)")
	out := flag.String("out", "", "path to write the JSON response (required)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("probe_pool", version)
		return
	}
	if *in == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "probe_pool: both -in and -out are required")
		os.Exit(2)
	}

	raw, err := os.ReadFile(*in)
	if err != nil {
		fail(*out, fmt.Sprintf("read request: %v", err))
	}
	var req batchRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		fail(*out, fmt.Sprintf("parse request: %v", err))
	}
	if len(req.Hosts) == 0 {
		fail(*out, "empty batch")
	}
	if len(req.Hosts) > maxBatch {
		req.Hosts = req.Hosts[:maxBatch]
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
				results[i] = executeProbe(req, req.Hosts[i])
			}
		}()
	}
	for i := range req.Hosts {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	encoded, err := json.Marshal(batchResponse{Results: results})
	if err != nil {
		fail(*out, fmt.Sprintf("encode response: %v", err))
	}
	if err := os.WriteFile(*out, append(encoded, '\n'), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "probe_pool: write response: %v\n", err)
		os.Exit(1)
	}
}

func fail(outPath, msg string) {
	// The daemon treats a missing/unparsable response as "pool unavailable" and
	// falls back to shell workers, but an explicit error record is friendlier
	// for the log than silence.
	resp, _ := json.Marshal(batchResponse{Results: []probeResult{{ID: "", Host: "", Code: "000", Error: msg}}})
	_ = os.WriteFile(outPath, append(resp, '\n'), 0644)
	fmt.Fprintf(os.Stderr, "probe_pool: %s\n", msg)
	os.Exit(1)
}

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
		if ip, ok := req.Resolve[h.Host]; ok && ip != "" {
			pin = ip
			res.IP = ip
		}
	}

	h2 := h.HTTP2 || req.HTTP2
	start := time.Now()

	// HTTPS first, mirroring the shell worker.
	code, fp, bodyLen, bodyHead := httpAttempt(h, proxyURL, pin, 443, h2, timeout)
	if code == "000" {
		// HTTPS produced no response вЂ” retry plain HTTP (HTTP-only and
		// redirect-to-http sites). 4xx/5xx are NOT retried, same as curl flow.
		code, fp, bodyLen, bodyHead = httpAttempt(h, proxyURL, pin, 80, h2, timeout)
	}

	res.Code = code
	res.FP = fp
	res.BodyLen = bodyLen
	res.BodyHead = bodyHead
	res.RTTms = int(time.Since(start).Milliseconds())
	return res
}

func httpAttempt(h probeRequest, proxyURL, pin string, port int, h2 bool, timeout time.Duration) (code, fp string, bodyLen int, bodyHead string) {
	code = "000"
	targetPort := fmt.Sprintf("%d", port)
	hostPort := net.JoinHostPort(h.Host, targetPort)
	urlHost := hostPort
	if pin != "" {
		urlHost = net.JoinHostPort(pin, targetPort)
	}
	scheme := "https"
	if port == 80 {
		scheme = "http"
	}

	tr := newTransport(proxyURL, h.Host, h2)
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
		ForceAttemptHTTP2: h2,
		MaxIdleConns:      4,
		IdleConnTimeout:   30 * time.Second,
	}
	if proxyURL != "" {
		if u, err := url.Parse(proxyURL); err == nil {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	return tr
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
