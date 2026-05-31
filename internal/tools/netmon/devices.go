package netmon

import (
	"net"
	"net/netip"
	"sort"
	"strconv"
)

// GroupDevices groups connections by their LAN initiator (original-direction
// src), keeping only private, non-loopback/link-local/multicast sources on a LAN
// zone. Each device's destinations are split into Working (responded) and
// FailingDsts (no reply / SYN stuck) — the failing set is the hook into the
// strategy-picking workflow. MAC comes from conntrack (mac=) with the ARP table
// as a fallback; the bridge name (br0/br2) comes from ARP.
func GroupDevices(conns []Conn, arp []ARPEntry) []Device {
	byIP := make(map[netip.Addr]ARPEntry, len(arp))
	for _, a := range arp {
		byIP[a.IP] = a
	}

	type acc struct {
		dev     Device
		working map[string]bool
		failing map[string]bool
	}
	m := map[netip.Addr]*acc{}

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
		a := m[src]
		if a == nil {
			a = &acc{working: map[string]bool{}, failing: map[string]bool{}}
			a.dev.IP = src.String()
			a.dev.MAC = c.MAC
			if e, ok := byIP[src]; ok {
				a.dev.Iface = e.Device
				if a.dev.MAC == "" {
					a.dev.MAC = e.MAC
				}
			}
			m[src] = a
		}
		a.dev.Total++
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

	out := make([]Device, 0, len(m))
	for _, a := range m {
		a.dev.Working = sortedKeys(a.working)
		a.dev.FailingDsts = sortedKeys(a.failing)
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
