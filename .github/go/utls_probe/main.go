// utls_probe — native browser-fingerprint TLS probe for the Strategy Lab.
//
// ЗАЧЕМ (ч.232, вердикт пользователя 2026-11-07): вся лаборатория стратегий
// меряет curl-ом, а у curl свой TLS-отпечаток ClientHello. TSPU различает
// клиентов по ClientHello — живой факт: стратегия Default (fake+multidisorder)
// проходит ВСЕ роутерные пробы, но на телефоне YouTube не работает, а
// реально работающая стратегия в лаборатории не лидирует. Эту разницу curl
// измерить не может в принципе (utls у него нет, и на mipsle/aarch64 его
// не собрать из готовых утилит) — поэтому появляется ЭТОТ бинарник.
//
// ЧТО ДЕЛАЕТ: один TLS-хендшейк с НАСТОЯЩИМ браузерным ClientHello
// (uTLS-отпечаток, по умолчанию Chrome) на закреплённый IP (curl --resolve
// эквивалент) — тот же путь, что и curl-проба zapret_test.sh: тестовый
// nfqws2 на temp-очереди искажает наш ClientHello, TSPU дальше по тракту
// решает его судьбу. Вердикт = рукопожатие завершено. Это ровно тот сигнал,
// которого не хватало: «стратегия держит браузерный Hello», а не только
// curl-овый.
//
// ЧЕСТНЫЕ ГРАНИЦЫ (не прячем):
//   - resumption/PSK (повторные соединения браузера) не воспроизводится —
//     проба = первое соединение клиента;
//   - после хендшейка опциональный HTTP/1.1 GET (-get): работает только
//     когда сервер выбрал http/1.1 по ALPN; браузеры договариваются h2 —
//     тогда content-часть честно отсутствует (рукопожатие уже измерено);
//   - QUIC/HTTP-3 не меряется (qtls на 32-битных MIPS не собирается — §2.5).
//
// ПРИМЕРЫ:
//   utls_probe -host www.youtube.com -ip 142.250.x.x
//   utls_probe -host i.ytimg.com -ip 87.250.x.x -fp firefox -get /generate_204
//
// ВЫВОД (одна строка JSON на stdout):
//   {"ok":1,"host":"…","ip":"…","fp":"chrome","alpn":"h2","ver":"tls1.3",
//    "tls_ms":123,"code":0,"bytes":0}
//   {"ok":0,"host":"…","ip":"…","fp":"chrome","err":"timeout","tls_ms":0}
// Exit code всегда 0 — вердикт только в JSON (тот же контракт, что у
// probe_pool: вердикты считает шелл/ucode-сторона).
//
// Сборка (см. build.sh): CGO_ENABLED=0 GOOS=linux GOARCH=… go build
// -trimpath -ldflags="-s -w". Зависимость одна — refraction-networking/utls.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

const version = "1.0.0"

// Отпечатки на выбор. Ключ = значение -fp. По умолчанию chrome — самая
// массовая семья клиентских Hello в РУ-сетях (Chrome desktop + Android
// WebView наследуют ту же структуру); android — OkHttp (клиент большинства
// Android-приложений). Имена соответствуют utls v1.6.7.
var fps = map[string]utls.ClientHelloID{
	"chrome":  utls.HelloChrome_120,
	"firefox": utls.HelloFirefox_Auto,
	"edge":    utls.HelloEdge_Auto,
	"ios":     utls.HelloIOS_Auto,
	"android": utls.HelloAndroid_11_OkHttp,
	"360":     utls.Hello360_Auto,
	"qq":      utls.HelloQQ_Auto,
	"random":  utls.HelloRandomizedNoALPN,
}

type result struct {
	OK     int    `json:"ok"`
	Host   string `json:"host"`
	IP     string `json:"ip"`
	Port   int    `json:"port,omitempty"`
	FP     string `json:"fp"`
	ALPN   string `json:"alpn,omitempty"`
	Ver    string `json:"ver,omitempty"`
	TLSms  int64  `json:"tls_ms"`
	Code   int    `json:"code,omitempty"`
	Bytes  int    `json:"bytes,omitempty"`
	H1Get  bool   `json:"h1_get,omitempty"` // GET выполнялся (h1 согласован)
	Err    string `json:"err,omitempty"`
}

func tlsVerName(v uint16) string {
	switch v {
	case utls.VersionTLS10:
		return "tls1.0"
	case utls.VersionTLS11:
		return "tls1.1"
	case utls.VersionTLS12:
		return "tls1.2"
	case utls.VersionTLS13:
		return "tls1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

func errName(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	// Короткие честные классы вместо простыней строк Go: вердикт в JSON,
	// разворачивать детали будет лог.
	switch {
	case strings.Contains(s, "timeout"), strings.Contains(s, "deadline"):
		return "timeout"
	case strings.Contains(s, "refused"):
		return "refused"
	case strings.Contains(s, "unreachable"):
		return "unreachable"
	case strings.Contains(s, "reset"):
		return "reset"
	case strings.Contains(s, "certificate"), strings.Contains(s, "x509"):
		return "cert"
	case strings.Contains(s, "no route"):
		return "noroute"
	case strings.Contains(s, "EOF"):
		return "eof"
	}
	return "fail"
}

func main() {
	host := flag.String("host", "", "TLS SNI / HTTP Host (required)")
	ip := flag.String("ip", "", "pin the dial to this IP (curl --resolve equivalent; empty = resolve)")
	port := flag.Int("port", 443, "TCP port")
	fp := flag.String("fp", "chrome", "ClientHello fingerprint: chrome|firefox|edge|ios|android|360|qq|random")
	tmo := flag.Int("timeout", 10, "whole-probe timeout, seconds (like curl --max-time)")
	get := flag.String("get", "", "optional path for an HTTP/1.1 GET after the handshake (only when h1 negotiated)")
	insecure := flag.Bool("insecure", false, "skip certificate verification (DPI MITM shows up as handshake success with a foreign cert)")
	flag.Parse()

	res := result{Host: *host, IP: *ip, Port: *port, FP: *fp}
	defer func() {
		b, _ := json.Marshal(res)
		fmt.Println(string(b))
	}()

	hid, okFp := fps[*fp]
	if !okFp {
		res.Err = "unknown fingerprint: " + *fp
		return
	}
	if *host == "" {
		res.Err = "no host"
		return
	}
	addr := net.JoinHostPort(*ip, strconv.Itoa(*port))
	if *ip == "" {
		addr = net.JoinHostPort(*host, strconv.Itoa(*port))
	}

	deadline := time.Now().Add(time.Duration(*tmo) * time.Second)

	t0 := time.Now()
	d := &net.Dialer{Deadline: deadline, Timeout: time.Duration(*tmo) * time.Second}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		res.Err = errName(err)
		return
	}
	defer conn.Close()
	conn.SetDeadline(deadline)

	cfg := &utls.Config{
		ServerName:         *host,
		InsecureSkipVerify: *insecure,
	}
	tc := utls.UClient(conn, cfg, hid)
	if err := tc.Handshake(); err != nil {
		res.Err = errName(err)
		return
	}
	st := tc.ConnectionState()
	res.TLSms = time.Since(t0).Milliseconds()
	res.Ver = tlsVerName(st.Version)
	res.ALPN = st.NegotiatedProtocol
	res.OK = 1

	// Опциональный content-проб: ТОЛЬКО когда сервер выбрал http/1.1
	// (браузеры договариваются h2 — там честно не делаем, граница в шапке).
	if *get != "" && (res.ALPN == "http/1.1" || res.ALPN == "") {
		res.H1Get = true
		req := "GET " + *get + " HTTP/1.1\r\n" +
			"Host: " + *host + "\r\n" +
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\n" +
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n" +
			"Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7\r\n" +
			"Connection: close\r\n\r\n"
		if _, err := tc.Write([]byte(req)); err != nil {
			res.Err = errName(err)
			res.Code = 0
			return
		}
		br := bufio.NewReaderSize(tc, 4096)
		tp := make([]byte, 0, 4096)
		for {
			line, err := br.ReadString('\n')
			tp = append(tp, []byte(line)...)
			if err != nil || strings.TrimSpace(line) == "" {
				break
			}
		}
		head := string(tp)
		code := 0
		if i := strings.Index(head, " "); i > 0 && strings.HasPrefix(head, "HTTP/") {
			code, _ = strconv.Atoi(strings.SplitN(head[i+1:], " ", 2)[0])
		}
		res.Code = code
		// Тело считаем, но не храним (вердикт — факт ответа и объём).
		n, _ := io_ReadAll(br)
		res.Bytes = n
	}
}

// Лимитированное чтение тела: максимум 64 КиБ — вердикту достаточно факта
// потока байтов, память роутера не расходуем.
func io_ReadAll(br *bufio.Reader) (int, error) {
	const limit = 64 * 1024
	buf := make([]byte, 4096)
	total := 0
	for total < limit {
		n, err := br.Read(buf)
		total += n
		if err != nil {
			return total, nil // EOF/ошибка после начала тела — не провал пробы
		}
	}
	return total, nil
}
