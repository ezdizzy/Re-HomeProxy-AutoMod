// sni_sniffer — native TLS ClientHello (SNI) capture for the HomeProxy
// automation engine.
//
// A tiny alternative to tcpdump for the automation "sni" discovery source:
// attaches a kernel BPF filter (dst port 443, PSH flag — the same heuristic
// the tcpdump path uses), parses TLS ClientHello records in userspace and
// appends one JSON line per unique hostname to an event file:
//
//	{"ts":1730000000,"host":"example.com","src":"192.168.1.10","dst":"1.2.3.4"}
//
// automation.uc tails the file (offset-based) and feeds the hosts into the
// normal discovery/probe pipeline; the file is rotated at ~512 KB so the
// tmpfs footprint stays bounded. Falls back gracefully: if the binary cannot
// start (no CAP_NET_RAW, exotic interface) the daemon keeps using tcpdump.
//
// Limitations (by design, same as the tcpdump path): IPv4 + TCP + non-fragmented
// Ethernet framing (br-lan), kernel filter assumes a 20-byte IP header — the
// identical assumption tcpdump's `tcp[13]` idiom makes.
//
// Build (see build.sh): CGO_ENABLED=0 GOOS=linux GOARCH=... go build -trimpath -ldflags="-s -w"
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const version = "1.1.0"

const (
	defaultIface  = "br-lan"
	defaultFile   = "/var/run/homeproxy/sni_events.jsonl"
	rotateSize    = 512 * 1024 // rotate the event file above this size
	dedupWindow   = 10 * time.Minute
	dedupMax      = 8192
	minPacketLen  = 54 // ethernet(14) + ip(20) + tcp(20)
	tcpDataOffset = 14 + 20
)

type sniEvent struct {
	TS   int64  `json:"ts"`
	Host string `json:"host"`
	Src  string `json:"src,omitempty"`
	Dst  string `json:"dst,omitempty"`
}

type eventFile struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

func (e *eventFile) write(evt sniEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.f == nil {
		f, err := os.OpenFile(e.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return
		}
		st, _ := f.Stat()
		if st != nil {
			e.size = st.Size()
		}
		e.f = f
	}
	line, err := json.Marshal(evt)
	if err != nil {
		return
	}
	line = append(line, '\n')
	if n, err := e.f.Write(line); err == nil {
		e.size += int64(n)
	}
	// Rotate by rename so the reader keeps a consistent inode; the next write
	// recreates the file and the daemon re-detects it (offset reset).
	if e.size >= rotateSize {
		e.f.Close()
		e.f = nil
		e.size = 0
		os.Rename(e.path, e.path+".old")
		os.Remove(e.path + ".old")
	}
}

func (e *eventFile) close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.f != nil {
		e.f.Close()
		e.f = nil
	}
}

var (
	events  eventFile
	seenMu  sync.Mutex
	seen    = make(map[string]int64)
	ch      = make(chan sniEvent, 256)
	iface   string
	dataDir string
)

func main() {
	flag.StringVar(&iface, "iface", defaultIface, "interface to capture on")
	flag.StringVar(&dataDir, "file", defaultFile, "JSONL event file to append to")
	debug := flag.Bool("debug", false, "log every captured SNI to stderr")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("sni_sniffer", version)
		return
	}
	log.SetFlags(log.LstdFlags)
	events = eventFile{path: dataDir}

	// Drain parsed events into the file so slow writes never block the capture loop.
	go func() {
		for evt := range ch {
			events.write(evt)
			if *debug {
				log.Printf("SNI %s (%s -> %s)", evt.Host, evt.Src, evt.Dst)
			}
		}
	}()

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		events.close()
		os.Exit(0)
	}()

	if err := capture(); err != nil {
		log.Printf("sni_sniffer: capture failed: %v", err)
		events.close()
		os.Exit(1)
	}
}

func capture() error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(uint16(syscall.ETH_P_ALL))))
	if err != nil {
		return fmt.Errorf("raw socket (need CAP_NET_RAW/root): %w", err)
	}
	defer syscall.Close(fd)

	ni, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface %s: %w", iface, err)
	}
	var sll syscall.SockaddrLinklayer
	sll.Protocol = htons(uint16(syscall.ETH_P_ALL))
	sll.Ifindex = ni.Index
	if err := syscall.Bind(fd, &sll); err != nil {
		return fmt.Errorf("bind %s: %w", iface, err)
	}

	if err := attachFilter(fd); err != nil {
		log.Printf("sni_sniffer: kernel filter not attached (%v) — parsing all packets", err)
	} else {
		log.Printf("sni_sniffer %s: capturing ClientHello on %s -> %s", version, iface, dataDir)
	}

	buf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return fmt.Errorf("recvfrom: %w", err)
		}
		if n >= minPacketLen {
			parsePacket(buf[:n])
		}
	}
}

// Kernel filter, byte offsets assume Ethernet + 20-byte IP header (the same
// assumption as the tcpdump `tcp[13] & 8` heuristic):
//   [12:14] ethertype == 0x0800
//   [23]    IP protocol == 6 (TCP)
//   [36:38] TCP dst port == 443
//   [47]    TCP flags, test PSH (0x08)
func attachFilter(fd int) error {
	const (
		ldh = 0x28
		ldb = 0x30
		jeq = 0x15
		jset = 0x45
		ret = 0x06
		acceptK = 0x00040000
	)
	filter := []syscall.SockFilter{
		{Code: ldh, Jt: 0, Jf: 1, K: 0x0000000c},
		{Code: jeq, Jt: 0, Jf: 3, K: 0x00000800}, // not IPv4
		{Code: ldb, Jt: 0, Jf: 1, K: 0x00000017},
		{Code: jeq, Jt: 0, Jf: 2, K: 0x00000006}, // not TCP
		{Code: ldh, Jt: 0, Jf: 1, K: 0x00000024}, // TCP dst port
		{Code: jeq, Jt: 0, Jf: 3, K: 0x000001bb}, // not 443
		{Code: ldb, Jt: 0, Jf: 0, K: 0x0000002f}, // TCP flags (tcp[13])
		{Code: jset, Jt: 1, Jf: 0, K: 0x00000008},
		{Code: ret, Jt: 0, Jf: 0, K: acceptK},
		{Code: ret, Jt: 0, Jf: 0, K: 0x00000000},
	}
	prog := syscall.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ATTACH_FILTER,
		int(uintptr(unsafe.Pointer(&prog))))
}

func parsePacket(p []byte) {
	sni, src, dst := sniFromPacket(p)
	if sni == "" {
		return
	}
	if !dedup(sni) {
		return
	}
	select {
	case ch <- sniEvent{
		TS:   time.Now().Unix(),
		Host: sni,
		Src:  src,
		Dst:  dst,
	}:
	default: // channel full — drop, discovery is best-effort
	}
}

// sniFromPacket extracts the SNI hostname (and src/dst IPs) from one captured
// frame; empty string when the packet carries no ClientHello.
func sniFromPacket(p []byte) (sni, src, dst string) {
	// Skip VLAN tags (802.1Q single tag): ethertype then sits at 16, payload +4.
	if p[12] == 0x81 && p[13] == 0x00 && len(p) >= minPacketLen+4 {
		p = p[4:]
		if len(p) < minPacketLen {
			return
		}
	}
	if binary.BigEndian.Uint16(p[12:14]) != 0x0800 {
		return // not IPv4
	}
	if p[23] != 6 { // not TCP
		return
	}
	ihl := int(p[14]&0x0f) * 4
	if ihl < 20 {
		return
	}
	// Kernel filter already dropped fragments-with-offset; still verify DF/frag
	// cheaply: skip fragmented non-first packets (flags/offset field != 0x4000-only).
	frag := binary.BigEndian.Uint16(p[20+6 : 20+8])
	if frag&0x1fff != 0 {
		return
	}
	tcp := 14 + ihl
	if len(p) < tcp+20 {
		return
	}
	dport := binary.BigEndian.Uint16(p[tcp+2 : tcp+4])
	if dport != 443 {
		return
	}
	flags := p[tcp+13]
	if flags&0x08 == 0 { // no PSH — not carrying payload
		return
	}
	tcpHdrLen := int(p[tcp+12]>>4) * 4
	if tcpHdrLen < 20 {
		return
	}
	payload := tcp + tcpHdrLen
	if len(p) < payload+6 {
		return
	}
	sni = parseClientHello(p[payload:])
	if sni == "" {
		return
	}
	src = net.IP(p[26:30]).String()
	dst = net.IP(p[30:34]).String()
	return sni, src, dst
}

// parseClientHello walks the TLS record в†’ handshake в†’ ClientHello extensions
// and returns the server_name. Returns "" for everything else. All reads are
// bounds-checked against len(body).
func parseClientHello(body []byte) string {
	if len(body) < 6 || body[0] != 0x16 { // not a TLS handshake record
		return ""
	}
	ver := binary.BigEndian.Uint16(body[1:3])
	if ver < 0x0300 || ver > 0x0304 {
		return ""
	}
	recLen := int(binary.BigEndian.Uint16(body[3:5]))
	if 5+recLen > len(body) {
		recLen = len(body) - 5 // record may straddle TCP segments; use what we have
	}
	hs := body[5 : 5+recLen]
	if len(hs) < 4 || hs[0] != 0x01 { // not ClientHello
		return ""
	}
	pos := 4 // skip handshake header
	// client version (2) + random (32)
	if len(hs) < pos+34 {
		return ""
	}
	pos += 34
	// session id
	if len(hs) < pos+1 {
		return ""
	}
	pos += 1 + int(hs[pos])
	if len(hs) < pos+2 {
		return ""
	}
	// cipher suites
	pos += 2 + int(binary.BigEndian.Uint16(hs[pos:pos+2]))
	if len(hs) < pos+1 {
		return ""
	}
	// compression methods
	pos += 1 + int(hs[pos])
	if len(hs) < pos+2 {
		return ""
	}
	// extensions
	extLen := int(binary.BigEndian.Uint16(hs[pos : pos+2]))
	pos += 2
	end := pos + extLen
	if end > len(hs) {
		end = len(hs)
	}
	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(hs[pos : pos+2])
		extLen2 := int(binary.BigEndian.Uint16(hs[pos+2 : pos+4]))
		data := pos + 4
		if data+extLen2 > end {
			return ""
		}
		if extType == 0 && extLen2 > 5 { // server_name
			list := hs[data : data+extLen2]
			if len(list) >= 5 && list[2] == 0 { // host_name type
				nameLen := int(binary.BigEndian.Uint16(list[3:5]))
				if 5+nameLen <= len(list) && nameLen > 0 {
					name := string(list[5 : 5+nameLen])
					if validHostname(name) {
						return name
					}
				}
			}
			return ""
		}
		pos = data + extLen2
	}
	return ""
}

func validHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	// Real SNI values are lower-case hostnames; binary-noise pseudo-hostnames
	// from the tcpdump path can't happen here (proper field parsing), but keep
	// the underscore-tolerant shape check.
	return true
}

func dedup(host string) bool {
	now := time.Now().Unix()
	seenMu.Lock()
	defer seenMu.Unlock()
	if len(seen) > dedupMax {
		for h, t := range seen {
			if now-t > int64(dedupWindow/time.Second) {
				delete(seen, h)
			}
		}
		if len(seen) > dedupMax { // still bloated: drop everything
			seen = make(map[string]int64)
		}
	}
	if t, ok := seen[host]; ok && now-t < int64(dedupWindow/time.Second) {
		return false
	}
	seen[host] = now
	return true
}

func htons(i uint16) uint16 {
	return i<<8 | i>>8
}
