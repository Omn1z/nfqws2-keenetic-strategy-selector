package dnsroute

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const shadowLeaseFile = "shadow-dns-leases.json"
const shadowLeaseFileLimit = 16 * 1024

type shadowBootClock struct {
	bootID string
	uptime time.Duration
	now    time.Time
}

type shadowLeaseRecord struct {
	Interface     string    `json:"interface"`
	WANKey        string    `json:"wan_key"`
	ClientIP      string    `json:"client_ip"`
	Servers       []string  `json:"servers"`
	Expires       time.Time `json:"expires"`
	ExpiresBootNS int64     `json:"expires_boot_ns"`
	Stamp         string    `json:"dhcp_stamp"`
	LeaseSeconds  uint64    `json:"lease_seconds"`
}

type shadowLeaseDocument struct {
	Version     int                      `json:"version"`
	BootID      string                   `json:"boot_id"`
	SavedAt     time.Time                `json:"saved_at"`
	SavedBootNS int64                    `json:"saved_boot_ns"`
	Leases      []shadowLeaseRecord      `json:"leases"`
	DHCPTargets []shadowDHCPTargetRecord `json:"dhcp_targets,omitempty"`
}

type shadowDHCPTargetRecord struct {
	Interface string `json:"interface"`
	WANKey    string `json:"wan_key"`
	ClientIP  string `json:"client_ip"`
	ServerIP  string `json:"server_ip"`
	Stamp     string `json:"dhcp_stamp"`
}

func shadowDHCPTargetRecords(targets map[string]shadowDHCPTarget) []shadowDHCPTargetRecord {
	keys := make([]string, 0, len(targets))
	for iface := range targets {
		keys = append(keys, iface)
	}
	sort.Strings(keys)
	var records []shadowDHCPTargetRecord
	for _, iface := range keys {
		t := targets[iface]
		records = append(records, shadowDHCPTargetRecord{Interface: iface, WANKey: t.wanKey, ClientIP: t.clientIP.String(), ServerIP: t.serverIP.String(), Stamp: t.stamp})
	}
	return records
}

func shadowStateDigest(leases map[string]shadowRememberedLease, targets map[string]shadowDHCPTarget) string {
	if len(targets) == 0 {
		return shadowLeaseDigest(leases)
	}
	data, _ := json.Marshal(struct {
		Leases  []shadowLeaseRecord
		Targets []shadowDHCPTargetRecord
	}{shadowLeaseRecords(leases), shadowDHCPTargetRecords(targets)})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func sameShadowLease(a, b shadowRememberedLease) bool {
	return a.wanKey == b.wanKey && a.clientIP.Equal(b.clientIP) && a.stamp == b.stamp && a.leaseSeconds == b.leaseSeconds && slices.Equal(a.servers, b.servers)
}

func shadowLeaseRecords(leases map[string]shadowRememberedLease) []shadowLeaseRecord {
	keys := make([]string, 0, len(leases))
	for iface := range leases {
		keys = append(keys, iface)
	}
	sort.Strings(keys)
	result := make([]shadowLeaseRecord, 0, len(keys))
	for _, iface := range keys {
		lease := leases[iface]
		result = append(result, shadowLeaseRecord{Interface: iface, WANKey: lease.wanKey, ClientIP: lease.clientIP.String(), Servers: append([]string(nil), lease.servers...), Expires: lease.expires.UTC(), Stamp: lease.stamp, LeaseSeconds: lease.leaseSeconds})
	}
	return result
}

func shadowLeaseDigest(leases map[string]shadowRememberedLease) string {
	data, _ := json.Marshal(shadowLeaseRecords(leases))
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func validShadowBootID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func readShadowBootClock() (shadowBootClock, error) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return shadowBootClock{}, err
	}
	uptime, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return shadowBootClock{}, err
	}
	fields := strings.Fields(string(uptime))
	if len(fields) == 0 {
		return shadowBootClock{}, fmt.Errorf("missing kernel uptime")
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	id := strings.TrimSpace(string(boot))
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 || seconds > 1e9 || !validShadowBootID(id) {
		return shadowBootClock{}, fmt.Errorf("invalid kernel boot clock")
	}
	return shadowBootClock{bootID: id, uptime: time.Duration(seconds * float64(time.Second)), now: time.Now()}, nil
}

func encodeShadowLeases(leases map[string]shadowRememberedLease, clock shadowBootClock) ([]byte, error) {
	return encodeShadowState(leases, nil, clock)
}

func encodeShadowState(leases map[string]shadowRememberedLease, targets map[string]shadowDHCPTarget, clock shadowBootClock) ([]byte, error) {
	if !validShadowBootID(clock.bootID) || clock.uptime < 0 || clock.now.IsZero() || len(leases) > 8 || len(targets) > 8 {
		return nil, fmt.Errorf("invalid Shadow lease state")
	}
	doc := shadowLeaseDocument{Version: 1, BootID: clock.bootID, SavedAt: clock.now.UTC(), SavedBootNS: int64(clock.uptime), Leases: shadowLeaseRecords(leases), DHCPTargets: shadowDHCPTargetRecords(targets)}
	for i := range doc.Leases {
		lease := &doc.Leases[i]
		remaining := lease.Expires.Sub(clock.now)
		if remaining <= 0 || remaining > 7*24*time.Hour {
			return nil, fmt.Errorf("invalid Shadow lease expiry")
		}
		lease.ExpiresBootNS = int64(clock.uptime + remaining)
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	if len(data) > shadowLeaseFileLimit {
		return nil, fmt.Errorf("Shadow lease cache too large")
	}
	return data, nil
}

func decodeShadowLeases(data []byte, clock shadowBootClock) (map[string]shadowRememberedLease, error) {
	leases, _, err := decodeShadowState(data, clock)
	return leases, err
}

func decodeShadowState(data []byte, clock shadowBootClock) (map[string]shadowRememberedLease, map[string]shadowDHCPTarget, error) {
	if len(data) > shadowLeaseFileLimit || !validShadowBootID(clock.bootID) || clock.uptime < 0 || clock.now.IsZero() {
		return nil, nil, fmt.Errorf("invalid Shadow lease cache")
	}
	var doc shadowLeaseDocument
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return nil, nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, nil, fmt.Errorf("extra Shadow lease data")
	}
	if doc.Version != 1 || doc.BootID != clock.bootID || doc.SavedAt.IsZero() || clock.now.Before(doc.SavedAt) || doc.SavedBootNS < 0 || int64(clock.uptime) < doc.SavedBootNS || len(doc.Leases) > 8 || len(doc.DHCPTargets) > 8 {
		return nil, nil, fmt.Errorf("expired boot or clock rollback in Shadow lease cache")
	}
	targets := map[string]shadowDHCPTarget{}
	for _, item := range doc.DHCPTargets {
		client, server := net.ParseIP(item.ClientIP), net.ParseIP(item.ServerIP)
		if !validKeeneticInterface(item.Interface) || client.To4() == nil || server.To4() == nil || !client.IsGlobalUnicast() || !server.IsGlobalUnicast() || client.Equal(server) || item.WANKey == "" || len(item.WANKey) > 2048 || strings.ContainsAny(item.WANKey, "\r\n\x00") {
			return nil, nil, fmt.Errorf("invalid saved DHCP discovery target")
		}
		// A live DHCPINFORM discovery has no historical ACK timestamp and
		// conveys no address lease. Its peer can still be revalidated/requeried.
		if item.Stamp != "" {
			if _, err := time.Parse("Jan _2 15:04:05", item.Stamp); err != nil {
				return nil, nil, fmt.Errorf("invalid DHCP target timestamp")
			}
		}
		if _, duplicate := targets[item.Interface]; duplicate {
			return nil, nil, fmt.Errorf("duplicate DHCP discovery target")
		}
		targets[item.Interface] = shadowDHCPTarget{wanKey: item.WANKey, clientIP: client, serverIP: server, stamp: item.Stamp}
	}
	result := map[string]shadowRememberedLease{}
	for _, item := range doc.Leases {
		ip := net.ParseIP(item.ClientIP)
		if !validKeeneticInterface(item.Interface) || ip.To4() == nil || !ip.IsGlobalUnicast() || item.WANKey == "" || len(item.WANKey) > 2048 || strings.ContainsAny(item.WANKey, "\r\n\x00") || len(item.Stamp) > 32 || item.LeaseSeconds == 0 || item.LeaseSeconds >= 0xffffffff || len(item.Servers) == 0 || len(item.Servers) > 8 {
			return nil, nil, fmt.Errorf("invalid saved Shadow lease")
		}
		if _, err := time.Parse("Jan _2 15:04:05", item.Stamp); err != nil {
			return nil, nil, fmt.Errorf("invalid DHCP lease timestamp")
		}
		if _, duplicate := result[item.Interface]; duplicate {
			return nil, nil, fmt.Errorf("duplicate Shadow lease interface")
		}
		if len(filterShadowServers(item.Servers, nil)) != len(item.Servers) {
			return nil, nil, fmt.Errorf("invalid saved provider DNS")
		}
		lifetime := time.Duration(item.LeaseSeconds) * time.Second
		if lifetime > 7*24*time.Hour {
			lifetime = 7 * 24 * time.Hour
		}
		wallLifetime := item.Expires.Sub(doc.SavedAt)
		if wallLifetime <= 0 || wallLifetime > lifetime || item.ExpiresBootNS <= doc.SavedBootNS || item.ExpiresBootNS-doc.SavedBootNS > int64(lifetime) {
			return nil, nil, fmt.Errorf("invalid saved DHCP expiry")
		}
		remaining := item.Expires.Sub(clock.now)
		bootRemaining := time.Duration(item.ExpiresBootNS) - clock.uptime
		if bootRemaining < remaining {
			remaining = bootRemaining
		}
		if remaining <= 0 {
			continue
		}
		result[item.Interface] = shadowRememberedLease{wanKey: item.WANKey, clientIP: ip, servers: append([]string(nil), item.Servers...), expires: clock.now.Add(remaining), stamp: item.Stamp, leaseSeconds: item.LeaseSeconds}
	}
	return result, targets, nil
}

func readShadowLeaseFile(filename string, clock shadowBootClock) (map[string]shadowRememberedLease, error) {
	leases, _, err := readShadowStateFile(filename, clock)
	return leases, err
}

func readShadowStateFile(filename string, clock shadowBootClock) (map[string]shadowRememberedLease, map[string]shadowDHCPTarget, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > shadowLeaseFileLimit {
		return nil, nil, fmt.Errorf("invalid Shadow lease file")
	}
	f, err := os.Open(filename)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, shadowLeaseFileLimit+1))
	if err != nil {
		return nil, nil, err
	}
	return decodeShadowState(data, clock)
}

func writeShadowLeaseFile(filename string, data []byte) error {
	if len(data) > shadowLeaseFileLimit {
		return fmt.Errorf("Shadow lease cache too large")
	}
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(filename), ".shadow-leases-*")
	if err != nil {
		return err
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, filename)
}

func (a *Adapter) loadShadowLeases() {
	if a.shadow.leasesLoaded {
		return
	}
	a.shadow.leasesLoaded = true
	a.shadow.leases = map[string]shadowRememberedLease{}
	if clock, err := readShadowBootClock(); err == nil && a.cfg.DataDir != "" {
		if leases, targets, err := readShadowStateFile(filepath.Join(a.cfg.DataDir, shadowLeaseFile), clock); err == nil {
			a.shadow.leases = leases
			a.shadow.inform.targets = targets
		}
	}
	a.shadow.leaseDigest = shadowStateDigest(a.shadow.leases, a.shadow.inform.targets)
}

func (a *Adapter) saveShadowLeases() {
	if a.cfg.DataDir == "" {
		return
	}
	digest := shadowStateDigest(a.shadow.leases, a.shadow.inform.targets)
	if digest == a.shadow.leaseDigest {
		return
	}
	clock, err := readShadowBootClock()
	if err != nil {
		return
	}
	data, err := encodeShadowState(a.shadow.leases, a.shadow.inform.targets, clock)
	if err != nil {
		return
	}
	if err := writeShadowLeaseFile(filepath.Join(a.cfg.DataDir, shadowLeaseFile), data); err == nil {
		a.shadow.leaseDigest = digest
	}
}
