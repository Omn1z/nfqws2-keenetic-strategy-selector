package netmon

import (
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// GroupDevices groups connections by the LAN initiator's MAC address (with an
// IP fallback for MAC-less rows). Each Device aggregates EVERY address — v4
// and v6 — the same MAC produced, so a single device shows up once instead of
// once-per-address. The primary `IP` field still holds the v4 address (or the
// first v6 when no v4 exists) for backward-compat with callers that consume a
// single string; the full v6 list lives in `IPv6`.
//
// Each device's destinations are split into Working (responded) and
// FailingDsts (no reply / SYN stuck) — the failing set is the hook into the
// strategy-picking workflow. MAC comes from conntrack's `mac=` field (works
// for both families since the kernel attaches the LAN-side MAC to ipv6 conns
// too), with the v4 ARP table as a secondary fallback for the iface name.
func GroupDevices(conns []Conn, arp []ARPEntry, ndpByMAC map[string][]string) []Device {
	byIP := make(map[netip.Addr]ARPEntry, len(arp))
	for _, a := range arp {
		byIP[a.IP] = a
	}
	hostnames := HostnamesByMAC() // mac → friendly name from DHCP leases (best-effort)

	type acc struct {
		dev     Device
		v4      string          // first v4 source seen (becomes Device.IP)
		v6Set   map[string]bool // de-duped v6 sources (collected into Device.IPv6)
		working map[string]bool
		failing map[string]bool
	}
	// Key by MAC so v4 + v6 conntrack rows from the same device fold into one
	// entry. MAC-less rows fall back to a per-IP key prefixed with "ip:" so
	// they don't collide with real MAC keys.
	m := map[string]*acc{}

	for _, c := range conns {
		src := c.Src
		if !src.IsValid() || !src.IsPrivate() || src.IsLoopback() || src.IsLinkLocalUnicast() || src.IsMulticast() {
			continue
		}
		if c.Zone == "swan" { // WAN/router-originated, not a LAN device
			continue
		}
		if !meaningfulDst(c.Dst) { // drop mDNS/multicast/broadcast/link-local noise
			continue
		}
		mac := strings.ToLower(c.MAC)
		if mac == "" {
			if e, ok := byIP[src]; ok {
				mac = strings.ToLower(e.MAC)
			}
		}
		key := mac
		if key == "" {
			key = "ip:" + src.String()
		}
		a := m[key]
		if a == nil {
			a = &acc{
				v6Set:   map[string]bool{},
				working: map[string]bool{},
				failing: map[string]bool{},
			}
			a.dev.MAC = mac
			if e, ok := byIP[src]; ok {
				a.dev.Iface = e.Device
			}
			m[key] = a
		}
		// Track every address this MAC produced. First v4 wins the primary
		// `IP` slot; v6 addresses get aggregated.
		if src.Is4() {
			if a.v4 == "" {
				a.v4 = src.String()
			}
		} else {
			a.v6Set[src.String()] = true
		}
		a.dev.Total++
		a.dev.BytesUp += c.Bytes
		a.dev.BytesDown += c.ReplyBytes
		dst := c.Dst.String()
		if c.DstPort != 0 { // omit ":0" for portless protocols (icmp)
			dst = net.JoinHostPort(c.Dst.String(), strconv.Itoa(c.DstPort))
		}
		if c.Failing() {
			a.dev.Failing++
			a.failing[dst] = true
		} else {
			a.dev.Established++
			a.working[dst] = true
		}
	}

	// Backfill v6 from the kernel NDP cache. LAN clients use link-local
	// (`fe80::/10`) sources which the conntrack filter above rejects, so
	// without this step Device.IPv6 stays empty and the Trace pane has no
	// way to resolve `fe80::…` clients to a hostname.
	for mac, v6s := range ndpByMAC {
		mac = strings.ToLower(mac)
		a := m[mac]
		if a == nil {
			a = &acc{
				v6Set:   map[string]bool{},
				working: map[string]bool{},
				failing: map[string]bool{},
			}
			a.dev.MAC = mac
			m[mac] = a
		}
		for _, v := range v6s {
			a.v6Set[v] = true
		}
	}

	out := make([]Device, 0, len(m))
	for _, a := range m {
		// Primary IP: first v4 if any; else the first v6 (lexicographically).
		if a.v4 != "" {
			a.dev.IP = a.v4
		} else if len(a.v6Set) > 0 {
			a.dev.IP = sortedKeys(a.v6Set)[0]
		}
		if len(a.v6Set) > 0 {
			a.dev.IPv6 = sortedKeys(a.v6Set)
		}
		a.dev.Working = sortedKeys(a.working)
		a.dev.FailingDsts = sortedKeys(a.failing)
		if name, ok := hostnames[a.dev.MAC]; ok {
			a.dev.Hostname = name
		}
		out = append(out, a.dev)
	}
	// Most-failing devices first (they're the ones worth picking strategies for),
	// then by IP for stable ordering.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Failing != out[j].Failing {
			return out[i].Failing > out[j].Failing
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// meaningfulDst reports whether a destination is a real routable target worth
// showing (and worth picking strategies for). Multicast/broadcast/link-local/
// loopback/unspecified addresses (e.g. mDNS 224.0.0.251) are noise.
func meaningfulDst(a netip.Addr) bool {
	if !a.IsValid() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.IsLoopback() || a.IsUnspecified() {
		return false
	}
	if a.Is4() && a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false // limited broadcast
	}
	return true
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
