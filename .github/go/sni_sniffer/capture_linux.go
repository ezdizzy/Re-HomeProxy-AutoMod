//go:build linux

// Linux packet-capture half of sni_sniffer: AF_PACKET raw socket, kernel BPF
// filter, promiscuous-mode handling. Split from main.go so the parser (main.go)
// stays compilable — and unit-testable with real captured bytes — on any OS.

package main

import (
	"fmt"
	"log"
	"net"
	"syscall"
	"unsafe"
)

func init() {
	startCapture = platformCapture
	platformCleanup = func() {
		if promiscSet && promiscFd >= 0 {
			clearPromisc(promiscFd, iface)
		}
	}
}

var (
	promiscSet bool
	promiscFd  int = -1
)

func platformCapture() error {
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

	/* Promiscuous is REQUIRED on WiFi APs: the wireless firmware uploads only
	 * frames targeted at the host MAC unless the interface is in promiscuous
	 * mode, so transit LAN->WAN frames (the ClientHello flows we want) never
	 * reach a non-promiscuous packet socket — observed live on the target
	 * router: tcpdump (promiscuous) saw 443 transit frames, a non-promiscuous
	 * packet socket saw only router-terminated traffic. tcpdump sets
	 * IFF_PROMISC too; we restore the flag on shutdown. */
	promiscFd = fd
	promiscSet = setPromisc(fd, iface, true)
	if promiscSet {
		log.Printf("sni_sniffer: promiscuous mode enabled on %s", iface)
	} else {
		log.Printf("sni_sniffer: could not enable promiscuous mode on %s — transit frames may be missed", iface)
	}

	if nofilter {
		log.Printf("sni_sniffer: kernel filter DISABLED by -nofilter (debug)")
	} else if err := attachFilter(fd); err != nil {
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

// setPromisc toggles IFF_PROMISC on `name` via the packet socket fd.
// Returns true when the flag was set (and needs clearing on shutdown).
func setPromisc(fd int, name string, on bool) bool {
	var ifr [40]byte // struct ifreq
	copy(ifr[0:16], name)
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(syscall.SIOCGIFFLAGS), uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		return false
	}
	flags := (*int16)(unsafe.Pointer(&ifr[16])) // ifr_flags, native endianness
	if on {
		*flags |= syscall.IFF_PROMISC
	} else {
		*flags &^= syscall.IFF_PROMISC
	}
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(syscall.SIOCSIFFLAGS), uintptr(unsafe.Pointer(&ifr[0]))); e != 0 {
		return false
	}
	return true
}

func clearPromisc(fd int, name string) {
	setPromisc(fd, name, false)
}

// Kernel filter, byte offsets assume Ethernet + 20-byte IP header (the same
// assumption as the tcpdump `tcp[13] & 8` heuristic):
//   [12:14] ethertype == 0x0800
//   [23]    IP protocol == 6 (TCP)
//   [36:38] TCP dst port == 443
//   [47]    TCP flags, test PSH (0x08)
//
// All failing branches jump to the trailing `ret 0`; a passing frame reaches
// `ret acceptK` (keep the whole packet). The userspace parser re-verifies every
// condition, so a filter miss costs CPU only, never correctness.
func attachFilter(fd int) error {
	const (
		ldh = 0x28 // BPF_LD|BPF_H|BPF_ABS
		ldb = 0x30 // BPF_LD|BPF_B|BPF_ABS
		jeq = 0x15 // BPF_JMP|BPF_JEQ|BPF_K
		jset = 0x45 // BPF_JMP|BPF_JSET|BPF_K
		ret = 0x06 // BPF_RET|BPF_K
		acceptK = 0x00040000
	)
	filter := []syscall.SockFilter{
		{Code: ldh, Jt: 0, Jf: 8, K: 0x0000000c},
		{Code: jeq, Jt: 0, Jf: 7, K: 0x00000800}, // not IPv4 -> ret 0 (idx9)
		{Code: ldb, Jt: 0, Jf: 6, K: 0x00000017},
		{Code: jeq, Jt: 0, Jf: 5, K: 0x00000006}, // not TCP -> ret 0
		{Code: ldh, Jt: 0, Jf: 4, K: 0x00000024}, // TCP dst port
		{Code: jeq, Jt: 0, Jf: 3, K: 0x000001bb}, // not 443 -> ret 0
		{Code: ldb, Jt: 0, Jf: 0, K: 0x0000002f}, // TCP flags (tcp[13])
		{Code: jset, Jt: 0, Jf: 1, K: 0x00000008}, // no PSH -> ret 0; PSH -> accept
		{Code: ret, Jt: 0, Jf: 0, K: acceptK},
		{Code: ret, Jt: 0, Jf: 0, K: 0x00000000},
	}
	prog := syscall.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}
	// SO_ATTACH_FILTER takes a struct sock_fprog VALUE-BY-POINTER, not an int:
	// SetsockoptInt would hand the kernel a pointer-sized integer read from the
	// struct address — EINVAL (observed live). Stdlib syscall has no
	// SetsockoptSockFprog helper, so issue setsockopt(2) directly.
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd),
		uintptr(syscall.SOL_SOCKET), uintptr(syscall.SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(&prog)), unsafe.Sizeof(prog), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func htons(i uint16) uint16 {
	return i<<8 | i>>8
}
