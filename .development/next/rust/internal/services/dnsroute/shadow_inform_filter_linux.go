//go:build linux

package dnsroute

import "golang.org/x/sys/unix"

// An unconnected raw UDP socket also receives ordinary WAN UDP, including VPN
// and QUIC downloads. Discard those packets in the kernel before they can fill
// the receive queue or consume the bounded 512-read budget. This filter applies
// only to this socket's copies; it cannot block traffic or change the firewall.
// Full DHCP transaction/peer validation remains in parseShadowInformReply.
func attachShadowInformFilter(fd int) error {
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 0},               // 0: IPv4 version/IHL
		{Code: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, K: 0xf0},           // 1: version bits
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: 0x40, Jf: 13},   // 2: IPv4, else →16
		{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 0},               // 3: version/IHL again
		{Code: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, K: 0x0f},           // 4: header words
		{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, K: 5, Jf: 10},      // 5: at least 20 bytes, else →16
		{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 9},               // 6: IPv4 protocol
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: 17, Jf: 8},      // 7: UDP, else →16
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: 6},               // 8: IPv4 flags/fragment offset
		{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: 0x3fff, Jt: 6}, // 9: no MF/offset, else →16
		{Code: unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH, K: 0},              // 10: X = 4*(IHL), includes IP options
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_IND, K: 0},               // 11: UDP source port
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: 67, Jf: 3},      // 12: server 67, else →16
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_IND, K: 2},               // 13: UDP destination port
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: 68, Jf: 1},      // 14: client 68, else →16
		{Code: unix.BPF_RET | unix.BPF_K, K: 0xffffffff},                    // 15: retain full datagram
		{Code: unix.BPF_RET | unix.BPF_K, K: 0},                             // 16: discard this socket's copy
	}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]})
}
