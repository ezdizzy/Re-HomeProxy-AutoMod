package main

import "testing"

// Контракт вывода: вердикт только в JSON, exit code всегда 0 — шелл-сторона
// (zapret_test.sh) не должна гадать по кодам выхода.
func TestResultShape(t *testing.T) {
	r := result{OK: 1, Host: "h", IP: "1.2.3.4", FP: "chrome", TLSms: 12}
	if r.OK != 1 || r.FP != "chrome" {
		t.Fatalf("unexpected result shape: %+v", r)
	}
}

func TestErrName(t *testing.T) {
	cases := map[string]string{
		"dial tcp 1.2.3.4:443: i/o timeout":                  "timeout",
		"dial tcp: connection refused":                       "refused",
		"read: connection reset by peer":                     "reset",
		"tls: failed to verify certificate: x509: …":         "cert",
		"something entirely else":                            "fail",
	}
	for in, want := range cases {
		if got := errName(strErr(in)); got != want {
			t.Fatalf("errName(%q) = %q, want %q", in, got, want)
		}
	}
}

func strErr(s string) error { return &strErrType{s} }

type strErrType struct{ s string }

func (e *strErrType) Error() string { return e.s }

func TestTlsVerName(t *testing.T) {
	if tlsVerName(0x0304) != "tls1.3" {
		t.Fatalf("tls1.3 name wrong")
	}
	if tlsVerName(0x0303) != "tls1.2" {
		t.Fatalf("tls1.2 name wrong")
	}
}
