package app

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"nfqws2strategy/internal/services/strategy/core/catalog"
)

// The current runner probes HTTPS over IPv4 and its sandbox queues TCP/443
// only. A successful request cannot validate an HTTP/QUIC-only profile: none
// of that profile's desync instructions would have handled the probe.
// Inspect argv, not the informational L7 label, including legacy profiles
// without explicit filters. This is an applicability check, not an nfqws parser.
func validateHTTPSStrategy(argLine string) error {
	if err := catalog.Validate(argLine); err != nil {
		return err
	}
	tcpSeen, tcpMatches, otherTransport := false, false, false
	l3Seen, ipv4Matches, tlsMatches := false, false, true
	payloadMatches, desyncMatches := true, false
	for _, token := range strings.Fields(argLine) {
		key, value, _ := strings.Cut(token, "=")
		switch key {
		case "--skip", "--template", "--import":
			return fmt.Errorf("HTTPS-проверка не поддерживает %s", key)
		case "--filter-tcp":
			matches, err := httpsPortFilter(value)
			if err != nil {
				return err
			}
			tcpSeen, tcpMatches = true, tcpMatches || matches
		case "--filter-udp", "--filter-icmp", "--filter-ipp":
			otherTransport = true
		case "--filter-l3":
			l3Seen = true
			ipv4Matches = ipv4Matches || slices.Contains(strings.Split(value, ","), "ipv4")
		case "--filter-l7":
			// Unlike port/L3 filters, a repeated L7 filter replaces the old one.
			tlsMatches = httpsProtocolFilter(value, "tls")
		case "--payload":
			// Payload selectors apply to the subsequent lua-desync instructions,
			// not retroactively to every instruction in the profile.
			payloadMatches = httpsProtocolFilter(value, "tls_client_hello")
		case "--lua-desync":
			method, _, _ := strings.Cut(value, ":")
			instanceMatches := payloadMatches
			for _, parameter := range strings.Split(value, ":")[1:] {
				if payload, ok := strings.CutPrefix(parameter, "payload="); ok {
					instanceMatches = instanceMatches && httpsProtocolFilter(payload, "tls_client_hello")
				}
			}
			if method != "" && method != "http_methodeol" && instanceMatches {
				desyncMatches = true
			}
		case "--dpi-desync":
			desyncMatches = desyncMatches || value != ""
		}
	}
	if (tcpSeen && !tcpMatches) || (!tcpSeen && otherTransport) || (l3Seen && !ipv4Matches) || !tlsMatches || !desyncMatches {
		return fmt.Errorf("стратегия не обрабатывает HTTPS (IPv4, TCP/443, TLS); HTTP/QUIC нельзя оценивать HTTPS-проверкой")
	}
	return nil
}

func httpsProtocolFilter(value, protocol string) bool {
	// Lua's leading '~' negates the entire payload list. Do not infer TLS
	// applicability from a later positive-looking item in that expression.
	if strings.HasPrefix(value, "~") {
		return false
	}
	for _, item := range strings.Split(value, ",") {
		if item == protocol || item == "all" || item == "known" {
			return true
		}
	}
	return false
}

// nfqws port filter entries (also across repeated --filter-tcp) are ORed;
// ~ negates one entry. Ranges use '-', whereas ':' belongs to iptables syntax.
func httpsPortFilter(value string) (bool, error) {
	matched := false
	for _, item := range strings.Split(value, ",") {
		if item == "*" {
			matched = true
			continue
		}
		negated := strings.HasPrefix(item, "~")
		item = strings.TrimPrefix(item, "~")
		loText, hiText, ranged := strings.Cut(item, "-")
		if !ranged {
			hiText = loText
		}
		lo, loErr := strconv.ParseUint(loText, 10, 16)
		hi, hiErr := strconv.ParseUint(hiText, 10, 16)
		if loErr != nil || hiErr != nil || lo > hi {
			return false, fmt.Errorf("некорректный фильтр TCP-портов для HTTPS-проверки: %q", value)
		}
		contains := lo <= 443 && 443 <= hi
		matched = matched || (contains != negated)
	}
	return matched, nil
}

func httpsRunStrategies(strategies []catalog.Strategy) []catalog.Strategy {
	out := make([]catalog.Strategy, 0, len(strategies))
	for _, strategy := range strategies {
		if validateHTTPSStrategy(strategy.ArgLine) == nil {
			out = append(out, strategy)
		}
	}
	return out
}
