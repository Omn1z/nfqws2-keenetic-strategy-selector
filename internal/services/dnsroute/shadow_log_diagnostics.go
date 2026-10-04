package dnsroute

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	shadowNativeLogBytes   = 1 << 20
	shadowNativeLogRecord  = 4096
	shadowNativeLogLeases  = 4
	shadowNativeLogDetails = 6
)

// logShadowNativeLeases explains the evidence available to the existing lease
// parser. It never supplies DNS candidates or changes the parser's decisions.
// Native messages are reduced to fixed labels, validated addresses and times;
// unrelated log text, even adjacent continuation lines, must not be exported.
func logShadowNativeLeases(ctx context.Context, output string, leases []keeneticShadowLease, routerNow time.Time) {
	if !shadowDiagnosticEnabled(ctx) {
		return
	}
	partial := len(output) > shadowNativeLogBytes
	if partial {
		output = output[len(output)-shadowNativeLogBytes:]
		_, output, _ = strings.Cut(output, "\n")
	}
	ackCount, obtainedCount, ignoredCount, associatedCount, skipped := 0, 0, 0, 0, 0
	details := make([]string, 0, shadowNativeLogDetails)
	addDetail := func(message string) {
		if len(details) == shadowNativeLogDetails {
			copy(details, details[1:])
			details = details[:len(details)-1]
		}
		details = append(details, message)
	}
	iface, stamp, obtained, remaining := "", "", false, 0
	var client net.IP
	consume := func(record string) {
		end := strings.Index(record, "] ")
		if end < 3 {
			return
		}
		timestamp, message := record[3:end], record[end+2:]
		if strings.HasPrefix(message, "ndhcpc: ") {
			iface, client, obtained, remaining = "", nil, false, 0
			fields := strings.Fields(strings.TrimPrefix(message, "ndhcpc: "))
			if len(fields) < 9 || fields[1] != "received" || fields[2] != "ACK" || fields[3] != "for" || fields[5] != "from" {
				return
			}
			name, ip := strings.TrimSuffix(fields[0], ":"), net.ParseIP(fields[4])
			if !validKeeneticInterface(name) || ip == nil {
				return
			}
			ackCount++
			iface, client, stamp, remaining = name, ip, timestamp, 16
			return
		}
		if timestamp != stamp || remaining == 0 {
			iface, obtained = "", false
		}
		if remaining > 0 {
			remaining--
		}
		if strings.HasPrefix(message, "ndm: Dhcp::Client: obtained IP address ") {
			address := strings.TrimSuffix(strings.TrimPrefix(message, "ndm: Dhcp::Client: obtained IP address "), ".")
			ip, _, err := net.ParseCIDR(address)
			obtained = err == nil && iface != "" && ip.Equal(client)
			if err == nil {
				obtainedCount++
				linked := "нет"
				if obtained {
					linked = iface
				}
				addDetail(fmt.Sprintf("obtained: время=%s; адрес=%s; связь с ACK=%s", shadowNativeLogTime(timestamp), ip, linked))
			}
		}
		if strings.HasPrefix(message, "ndm: Dns::InterfaceSpecific: name server ") && strings.HasSuffix(message, " is ignored.") {
			address := strings.TrimSuffix(strings.TrimPrefix(message, "ndm: Dns::InterfaceSpecific: name server "), " is ignored.")
			if ip := net.ParseIP(address); ip != nil {
				ignoredCount++
				linked := "нет (нет подходящей пары ACK/obtained в окне парсера)"
				if obtained && iface != "" {
					linked = iface
					associatedCount++
				}
				addDetail(fmt.Sprintf("ignored DNS: время=%s; адрес=%s; связь с ACK=%s", shadowNativeLogTime(timestamp), ip, linked))
			}
		}
	}
	// Join the same wrapped native records as the lease parser, with a strict
	// per-record bound so arbitrary native output cannot grow diagnostics work.
	record, oversized := "", false
	flush := func() {
		if record != "" && !oversized {
			consume(record)
		} else if oversized {
			skipped++
			// A discarded record must not create a false adjacent association.
			iface, obtained, remaining = "", false, 0
		}
	}
	for line := range strings.SplitSeq(output, "\n") {
		line = strings.TrimRight(strings.ReplaceAll(line, "\x1b[K", ""), "\r")
		if len(line) > 4 && line[1:3] == " [" {
			flush()
			record, oversized = "", len(line) > shadowNativeLogRecord
			if !oversized {
				record = strings.TrimSpace(line)
			}
		} else if record != "" && !oversized && strings.HasPrefix(line, " ") {
			line = strings.TrimSpace(line)
			if len(record)+len(line)+1 > shadowNativeLogRecord {
				oversized = true
			} else {
				record += " " + line
			}
		}
	}
	flush()
	shownLeases := min(len(leases), shadowNativeLogLeases)
	shadowDiagnosticEvent(ctx, "native.log.summary", fmt.Sprintf("Журнал: ACK=%d; obtained=%d; ignored DNS=%d; связанных ignored DNS=%d; последних аренд=%d (показано %d); показано записей=%d; часть журнала пропущена=%t; слишком длинных записей=%d", ackCount, obtainedCount, ignoredCount, associatedCount, len(leases), shownLeases, len(details), partial, skipped), 0)
	for _, lease := range leases[len(leases)-shownLeases:] {
		name := "невалидный интерфейс"
		if validKeeneticInterface(lease.iface) {
			name = lease.iface
		}
		age, reason := "неизвестен", "DNS присутствуют; требуется проверка активного WAN и адресов"
		observed := shadowLeaseObservedAt(lease.stamp, routerNow)
		remaining := shadowLeaseRemaining(lease, routerNow)
		if !observed.IsZero() {
			age = fmt.Sprintf("%d с", max(0, int64(routerNow.Sub(observed)/time.Second)))
		}
		switch {
		case observed.IsZero():
			reason = "недоступно время роутера или timestamp ACK"
		case lease.leaseSeconds == 0 || lease.leaseSeconds >= 0xffffffff:
			reason = "нет ограниченного срока аренды"
		case remaining == 0:
			reason = "аренда истекла"
		case len(lease.servers) == 0:
			reason = "DNS не связаны с последним ACK (нужны obtained и ignored DNS с тем же временем в пределах 16 записей)"
		}
		shadowDiagnosticEvent(ctx, "native.log.lease", fmt.Sprintf("%s: ACK=%s; возраст=%s; lease=%d с; остаток=%d с; DNS=%d; %s", name, shadowNativeLogTime(lease.stamp), age, lease.leaseSeconds, int64(remaining/time.Second), len(lease.servers), reason), 0)
	}
	for _, detail := range details {
		shadowDiagnosticEvent(ctx, "native.log.record", detail, 0)
	}
}

func shadowNativeLogTime(stamp string) string {
	parsed, err := time.Parse("Jan _2 15:04:05", stamp)
	if err != nil {
		return "невалидное время"
	}
	return parsed.Format("Jan 02 15:04:05")
}
