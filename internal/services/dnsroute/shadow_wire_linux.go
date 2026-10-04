//go:build linux

package dnsroute

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

const shadowWireMaxReads = 32
const shadowWireMaxEvents = 8

// This passive socket sees DHCP before the IP INPUT path. It never sends,
// changes interface flags, occupies port 68 or consumes the DHCP client's copy.
// Only the current short INFORM exchange is observed; there is no background
// worker, disk capture or dependency on tcpdump. Failure is diagnostic only.
func startShadowWireCapture(ctx context.Context, nic *net.Interface, id shadowInformIdentity, discover bool) func() {
	if !shadowDiagnosticEnabled(ctx) {
		return func() {}
	}
	started := time.Now()
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		shadowDiagnosticEvent(ctx, "wire.error", "Захват DHCP недоступен: "+err.Error(), 0)
		return func() {}
	}
	setup := func() error {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 16*1024); err != nil {
			return err
		}
		if err := attachShadowWireFilter(fd); err != nil {
			return err
		}
		// ETH_P_ALL is required to observe outgoing packets too. The kernel
		// filter below keeps only IPv4 DHCP; NativeEndian also handles MIPS BE.
		protocol := binary.NativeEndian.Uint16([]byte{0, unix.ETH_P_ALL})
		return unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: protocol, Ifindex: nic.Index})
	}
	if err := setup(); err != nil {
		_ = unix.Close(fd)
		shadowDiagnosticEvent(ctx, "wire.error", "Не удалось включить захват DHCP: "+err.Error(), 0)
		return func() {}
	}
	shadowDiagnosticEvent(ctx, "wire.start", fmt.Sprintf("Захват на %s: IPv4 UDP 67↔68, только время текущей попытки; без promiscuous mode", nic.Name), 0)
	return func() {
		defer unix.Close(fd)
		buffer := make([]byte, 1536)
		packets, outgoing, incoming, unrelated, shown := 0, 0, 0, 0, 0
		for packets < shadowWireMaxReads {
			n, address, err := unix.Recvfrom(fd, buffer, unix.MSG_DONTWAIT)
			if err != nil {
				if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
					shadowDiagnosticEvent(ctx, "wire.error", "Чтение захвата DHCP: "+err.Error(), 0)
				}
				break
			}
			packets++
			if n < 0 || n > len(buffer) {
				unrelated++
				continue
			}
			link, ok := address.(*unix.SockaddrLinklayer)
			if !ok || link.Ifindex != nic.Index {
				unrelated++
				continue
			}
			isOutgoing := link.Pkttype == unix.PACKET_OUTGOING
			message, matches := shadowWirePacketSummary(buffer[:n], id, discover, isOutgoing)
			if !matches {
				unrelated++
				continue
			}
			if isOutgoing {
				outgoing++
			} else {
				incoming++
			}
			if shown < shadowWireMaxEvents {
				shadowDiagnosticEvent(ctx, "wire.packet", message, 0)
				shown++
			}
		}
		statsText := ""
		if stats, err := unix.GetsockoptTpacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS); err == nil {
			statsText = fmt.Sprintf("; в сокет захвата=%d, потеряно=%d", stats.Packets, stats.Drops)
		}
		shadowDiagnosticEvent(ctx, "wire.finish", fmt.Sprintf("DHCP текущей транзакции на WAN: исходящих=%d, входящих=%d; посторонних/неполных=%d; предел чтения=%t%s. Нулевой счётчик не доказывает отсутствие пакета вне окна захвата.", outgoing, incoming, unrelated, packets == shadowWireMaxReads, statsText), time.Since(started))
	}
}

// Packet metadata is emitted only for this random XID and client MAC. Other
// subscribers' DHCP packets are counted but their addresses/options are omitted.
func shadowWirePacketSummary(packet []byte, id shadowInformIdentity, discover, outgoing bool) (string, bool) {
	if len(packet) < 20 || packet[0]>>4 != 4 || packet[9] != 17 {
		return "", false
	}
	ihl := int(packet[0]&15) * 4
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if ihl < 20 || total < ihl+8+240 || total > len(packet) || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return "", false
	}
	udp := packet[ihl:total]
	length := int(binary.BigEndian.Uint16(udp[4:6]))
	if length < 8+240 || length > len(udp) {
		return "", false
	}
	srcPort, dstPort := binary.BigEndian.Uint16(udp[:2]), binary.BigEndian.Uint16(udp[2:4])
	if !(srcPort == 68 && dstPort == 67 || srcPort == 67 && dstPort == 68) {
		return "", false
	}
	dhcp := udp[8:length]
	if dhcp[1] != 1 || dhcp[2] != 6 || !bytes.Equal(dhcp[4:8], id.xid[:]) || !bytes.Equal(dhcp[28:34], id.mac[:]) {
		return "", false
	}
	direction := "входящий"
	if outgoing {
		direction = "исходящий"
	}
	options := map[byte][]byte{}
	optionErr := parseShadowInformOptions(dhcp[240:], options)
	messageType := "неизвестен"
	if value := options[53]; len(value) == 1 {
		switch value[0] {
		case 5:
			messageType = "ACK"
		case 6:
			messageType = "NAK"
		case 8:
			messageType = "INFORM"
		default:
			messageType = fmt.Sprint(value[0])
		}
	}
	server := "отсутствует"
	if value := options[54]; len(value) == 4 {
		server = net.IP(value).String()
	}
	message := fmt.Sprintf("%s %s:%d → %s:%d; DHCP=%s, xid=%x, server-id=%s, ciaddr=%s, yiaddr=%s, relay=%s", direction, net.IP(packet[12:16]), srcPort, net.IP(packet[16:20]), dstPort, messageType, id.xid, server, net.IP(dhcp[12:16]), net.IP(dhcp[16:20]), net.IP(dhcp[24:28]))
	if optionErr != nil {
		message += "; options: " + optionErr.Error()
	}
	if !outgoing {
		if _, _, err := parseShadowInformACK(packet, id, discover); err != nil {
			message += "; проверка ответа: " + err.Error()
		} else {
			message += "; проверка ответа: OK"
		}
	}
	return message, true
}

func attachShadowWireFilter(fd int) error {
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, K: 0xf0},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: 0x40, Jf: 17}, // →20 drop
		{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, K: 0x0f},
		{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, K: 5, Jf: 14},
		{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 9},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: 17, Jf: 12},
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: 6},
		{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: 0x3fff, Jt: 10},
		{Code: unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH, K: 0},
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_IND, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: 67, Jt: 1},        // →14
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: 68, Jt: 3, Jf: 6}, // →17 or20
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_IND, K: 2},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: 68, Jt: 3, Jf: 4}, // →19 or20
		{Code: unix.BPF_RET | unix.BPF_K, K: 0},
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_IND, K: 2},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: 67, Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: 1536},
		{Code: unix.BPF_RET | unix.BPF_K, K: 0},
	}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]})
}
