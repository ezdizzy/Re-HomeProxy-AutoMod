package main

import (
	"encoding/binary"
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
		buildClientHello(t, "x"), // SNI shorter than the list rules falls out
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
