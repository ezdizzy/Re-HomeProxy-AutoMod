package main

import (
	"encoding/binary"
	"os"
	"testing"
)

// buildClientHello assembles ethernet+IP+TCP+TLS record bytes carrying a
// ClientHello with (or without) a server_name extension.
func buildClientHello(t *testing.T, sni string) []byte {
	t.Helper()

	// TLS payload: handshake ClientHello
	hs := []byte{0x01, 0x00, 0x00, 0x00} // handshake header, len filled later
	hs = append(hs, 0x03, 0x03)          // client version TLS1.2
	hs = append(hs, make([]byte, 32)...) // random
	hs = append(hs, 0x00)                // session id len
	hs = append(hs, 0x00, 0x02, 0x13, 0x01) // cipher suites
	hs = append(hs, 0x01, 0x00)          // compression: null

	if sni != "" {
		// server_name_list
		name := []byte(sni)
		entry := append([]byte{0x00, byte(len(name) >> 8), byte(len(name))}, name...)
		list := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
		ext := append([]byte{0x00, 0x00, byte(len(list) >> 8), byte(len(list))}, list...)

		other := []byte{0x00, 0x17, 0x00, 0x00} // extension type 23, empty
		exts := append(ext, other...)
		hs = append(hs, byte(len(exts)>>8), byte(len(exts)))
		hs = append(hs, exts...)
	} else {
		hs = append(hs, 0x00, 0x00)
	}
	binary.BigEndian.PutUint32(hs[0:4], uint32(len(hs)-4))
	hs[0] = 0x01 // restore the handshake type clobbered by the 32-bit length write

	// TLS record
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)

	// TCP header (20 bytes, data offset 5, PSH+ACK)
	tcp := make([]byte, 20)
	tcp[12] = 5 << 4
	tcp[13] = 0x18 // PSH|ACK
	binary.BigEndian.PutUint16(tcp[2:4], 443)

	// IPv4 header (20 bytes, proto 6)
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[9] = 6
	copy(ip[12:16], []byte{192, 168, 1, 10})
	copy(ip[16:20], []byte{1, 2, 3, 4})

	eth := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x08, 0x00}

	out := append(eth, ip...)
	out = append(out, tcp...)
	return append(out, rec...)
}

func TestParseClientHelloWithSNI(t *testing.T) {
	pkt := buildClientHello(t, "www.example.org")
	got, src, dst := sniFromPacket(pkt)
	if got != "www.example.org" {
		t.Fatalf("want www.example.org, got %q", got)
	}
	if src != "192.168.1.10" || dst != "1.2.3.4" {
		t.Fatalf("bad src/dst: %q -> %q", src, dst)
	}
}

func TestParseClientHelloWithoutSNI(t *testing.T) {
	pkt := buildClientHello(t, "")
	if got, _, _ := sniFromPacket(pkt); got != "" {
		t.Fatalf("want empty, got %q", got)
	}
}

func TestParseClientHelloRejectsGarbage(t *testing.T) {
	for _, p := range [][]byte{
		nil,
		make([]byte, 53),
		buildClientHello(t, "bad host.ru!"), // invalid hostname chars fall out
	} {
		if got, _, _ := sniFromPacket(p); got != "" {
			t.Fatalf("want empty for junk, got %q", got)
		}
	}
}

func TestValidHostname(t *testing.T) {
	if !validHostname("a.b.c-example_mirrors") {
		t.Fatal("valid hostname rejected")
	}
	for _, s := range []string{"", "bad host.ru!", "a\x00b"} {
		if validHostname(s) {
			t.Fatalf("hostname %q must be rejected", s)
		}
	}
}

func TestDedup(t *testing.T) {
	seen = make(map[string]int64) // reset
	if !dedup("one.example") {
		t.Fatal("first sighting must pass")
	}
	if dedup("one.example") {
		t.Fatal("second sighting within the window must be deduped")
	}
	if !dedup("two.example") {
		t.Fatal("different host must pass")
	}
}

// TestRealPcap feeds REAL frames captured on the router (tcpdump -w, link-type
// EN10MB) through sniFromPacket. Enabled only when SNI_PCAP points to the pcap
// file: go test -run TestRealPcap (SNI_PCAP=cap.pcap). Catches parser breaks
// against live Chrome/Telegram/ECH ClientHellos that synthetic packets miss.
func TestRealPcap(t *testing.T) {
	path := os.Getenv("SNI_PCAP")
	if path == "" {
		t.Skip("SNI_PCAP not set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pcap: %v", err)
	}
	if len(data) < 24 {
		t.Fatal("pcap too small")
	}
	magic := binary.BigEndian.Uint32(data[0:4])
	var le bool
	switch magic {
	case 0xa1b2c3d4, 0xa1b23c4d: // big-endian (micro/nano)
	case 0xd4c3b2a1, 0x4d3cb2a1: // little-endian
		le = true
	default:
		t.Fatalf("not a pcap file (magic %x)", magic)
	}
	var order binary.ByteOrder = binary.LittleEndian
	if !le {
		order = binary.BigEndian
	}

	off := uint32(24)
	var frames, sniOK, parseFail443 int
	var seenHosts []string
	for off+16 <= uint32(len(data)) {
		incl := order.Uint32(data[off+8 : off+12])
		off += 16
		if incl == 0 || off+incl > uint32(len(data)) {
			break
		}
		frame := data[off : off+incl]
		off += incl
		if len(frame) < minPacketLen {
			continue
		}
		frames++
		sni, _, _ := sniFromPacket(frame)
		if sni != "" {
			sniOK++
			if len(seenHosts) < 20 {
				seenHosts = append(seenHosts, sni)
			}
			continue
		}
		// classify why it failed: did it look like a 443/PSH frame?
		if frame[12] == 0x81 && len(frame) > minPacketLen+4 {
			frame = frame[4:]
		}
		if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 || frame[23] != 6 {
			continue
		}
		ihl := int(frame[14]&0x0f) * 4
		if ihl < 20 {
			continue
		}
		tcp := 14 + ihl
		if len(frame) < tcp+20 {
			continue
		}
		if binary.BigEndian.Uint16(frame[tcp+2:tcp+4]) != 443 {
			continue
		}
		if frame[tcp+13]&0x08 == 0 {
			continue
		}
		parseFail443++
		if parseFail443 <= 3 {
			payload := frame[tcp+int(frame[tcp+12]>>4)*4:]
			t.Logf("UNPARSED 443/PSH frame len=%d payload=% x", len(frame), payload[:min(len(payload), 64)])
		}
	}
	t.Logf("pcap: %d frames parsed, %d SNI extracted, %d ClientHello-looking frames FAILED: %v", frames, sniOK, parseFail443, seenHosts)
	if sniOK == 0 {
		t.Errorf("no SNI extracted from a real capture with %d frames ? parser is broken on live traffic", frames)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestTraceRealClientHello dumps the parse walk for the first failing
// 443/PSH frame in the pcap (diagnostic; SNI_PCAP required).

