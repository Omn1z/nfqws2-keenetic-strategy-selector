package arpblock

import (
	"net"
	"sort"
	"strings"
)

// These are passive native tables; client names and MAC vendors do not prove
// a device's identity. No network probing or third-party lookup is performed.
func parseClients(associations, leases string, cfg NativeConfig) []Client {
	byMAC := map[string]Client{}
	for _, row := range nativeRecords(leases, "lease") {
		mac := clientMAC(row["mac"])
		if mac == "" {
			continue
		}
		ip := row["ip"]
		if net.ParseIP(ip) == nil {
			ip = ""
		}
		byMAC[mac] = Client{MAC: mac, IP: ip, Hostname: row["hostname"]}
	}
	out := []Client{}
	seen := map[string]bool{}
	for _, row := range nativeRecords(associations, "station") {
		mac := clientMAC(row["mac"])
		if mac == "" || seen[mac] {
			continue
		}
		seen[mac] = true
		client := byMAC[mac]
		client.MAC = mac
		client.AP = row["ap"]
		client.Segment = bridgeForAP(cfg, client.AP)
		out = append(out, client)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out
}

func clientMAC(raw string) string {
	mac, err := net.ParseMAC(raw)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
		return ""
	}
	if mac.String() == "00:00:00:00:00:00" {
		return ""
	}
	return mac.String()
}

func nativeRecords(text, marker string) []map[string]string {
	rows := []map[string]string{}
	var row map[string]string
	column := -1
	for _, line := range strings.Split(text, "\n") {
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		key, value := strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:])
		if key == marker && value == "" {
			row = map[string]string{}
			rows = append(rows, row)
			column = -1
			continue
		}
		if row == nil {
			continue
		}
		if column < 0 {
			column = i
		}
		if i != column {
			continue
		}
		switch key {
		case "mac", "ip", "hostname", "ap":
			if _, exists := row[key]; exists {
				row["mac"] = "invalid"
				continue
			}
			row[key] = value
		}
	}
	return rows
}
