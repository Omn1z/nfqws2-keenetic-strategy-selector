package dnsroute

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func shadowStoredFixture(t *testing.T) ([]byte, shadowBootClock, map[string]shadowRememberedLease) {
	t.Helper()
	clock := shadowBootClock{bootID: "01234567-89ab-cdef-0123-456789abcdef", uptime: 12 * time.Hour, now: time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)}
	leases := map[string]shadowRememberedLease{"ISP": {wanKey: "ip=192.168.0.10|route=eth3/192.168.0.1", clientIP: net.ParseIP("192.168.0.10"), servers: []string{"192.0.2.53:53"}, expires: clock.now.Add(time.Hour), stamp: "Oct  3 11:00:00", leaseSeconds: 7200}}
	wire, err := encodeShadowLeases(leases, clock)
	if err != nil {
		t.Fatal(err)
	}
	return wire, clock, leases
}

func TestShadowLeasePersistenceRestoresRealRemainingLifetime(t *testing.T) {
	wire, saved, leases := shadowStoredFixture(t)
	later := saved
	later.now, later.uptime = saved.now.Add(20*time.Minute), saved.uptime+20*time.Minute
	got, err := decodeShadowLeases(wire, later)
	if err != nil || len(got) != 1 || !sameShadowLease(got["ISP"], leases["ISP"]) || !got["ISP"].expires.Equal(leases["ISP"].expires) {
		t.Fatalf("restart: %+v %v", got, err)
	}
	if shadowLeaseDigest(got) != shadowLeaseDigest(leases) {
		t.Fatal("identical lease would cause a flash rewrite")
	}
	copy := got["ISP"]
	copy.servers[0] = "changed"
	if leases["ISP"].servers[0] == "changed" {
		t.Fatal("restored lease aliases source")
	}
	// A wall-clock rollback which remains after saved_at still cannot extend
	// the lease because the kernel boot clock is an independent upper bound.
	rolled := later
	rolled.now = saved.now.Add(10 * time.Minute)
	got, err = decodeShadowLeases(wire, rolled)
	if err != nil || got["ISP"].expires.Sub(rolled.now) != 40*time.Minute {
		t.Fatalf("partial rollback extended expiry: %+v %v", got, err)
	}
	whenExpired := saved
	whenExpired.now, whenExpired.uptime = saved.now.Add(time.Hour), saved.uptime+time.Hour
	if got, err := decodeShadowLeases(wire, whenExpired); err != nil || len(got) != 0 {
		t.Fatalf("expired: %+v %v", got, err)
	}
}

func TestShadowLeasePersistenceRejectsWrongBootClockAndMalformedState(t *testing.T) {
	wire, clock, _ := shadowStoredFixture(t)
	for _, modify := range []func(*shadowBootClock){
		func(c *shadowBootClock) { c.bootID = "11234567-89ab-cdef-0123-456789abcdef" },
		func(c *shadowBootClock) { c.now = c.now.Add(-time.Second) },
		func(c *shadowBootClock) { c.uptime -= time.Second },
	} {
		changed := clock
		modify(&changed)
		if got, err := decodeShadowLeases(wire, changed); err == nil {
			t.Fatalf("bad boot/clock accepted: %+v", got)
		}
	}
	for _, modify := range []func(*shadowLeaseDocument){
		func(d *shadowLeaseDocument) { d.Version = 2 },
		func(d *shadowLeaseDocument) { d.Leases[0].Servers = []string{"127.0.0.1:53"} },
		func(d *shadowLeaseDocument) { d.Leases[0].Servers = []string{"dns.example:53"} },
		func(d *shadowLeaseDocument) { d.Leases[0].Servers = []string{"192.0.2.53", "192.0.2.53:53"} },
		func(d *shadowLeaseDocument) { d.Leases[0].ClientIP = "not-ip" },
		func(d *shadowLeaseDocument) { d.Leases[0].Interface = "ISP;reboot" },
		func(d *shadowLeaseDocument) { d.Leases[0].Interface = "Wireguard0" },
		func(d *shadowLeaseDocument) { d.Leases[0].Expires = d.SavedAt.Add(48 * time.Hour) },
		func(d *shadowLeaseDocument) { d.Leases[0].ExpiresBootNS = d.SavedBootNS + int64(48*time.Hour) },
		func(d *shadowLeaseDocument) { d.Leases[0].LeaseSeconds = 0xffffffff },
		func(d *shadowLeaseDocument) { d.Leases[0].WANKey = strings.Repeat("x", 3000) },
		func(d *shadowLeaseDocument) { d.Leases = append(d.Leases, d.Leases[0]) },
	} {
		var doc shadowLeaseDocument
		if err := json.Unmarshal(wire, &doc); err != nil {
			t.Fatal(err)
		}
		modify(&doc)
		bad, _ := json.Marshal(doc)
		if got, err := decodeShadowLeases(bad, clock); err == nil {
			t.Fatalf("invalid state accepted: %+v", got)
		}
	}
	for _, bad := range [][]byte{[]byte("null"), []byte("{"), append(append([]byte(nil), wire...), []byte(" {}")...), []byte(strings.Repeat(" ", shadowLeaseFileLimit+1))} {
		if _, err := decodeShadowLeases(bad, clock); err == nil {
			t.Fatal("malformed/oversized cache accepted")
		}
	}
}

func TestShadowLeaseFileAtomicBoundedAndPrivate(t *testing.T) {
	wire, clock, leases := shadowStoredFixture(t)
	file := filepath.Join(t.TempDir(), "state", shadowLeaseFile)
	if err := writeShadowLeaseFile(file, wire); err != nil {
		t.Fatal(err)
	}
	got, err := readShadowLeaseFile(file, clock)
	if err != nil || shadowLeaseDigest(got) != shadowLeaseDigest(leases) {
		t.Fatalf("file roundtrip: %+v %v", got, err)
	}
	if info, err := os.Stat(file); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("permissions %v %v", info, err)
	}
	if err := writeShadowLeaseFile(file, []byte(strings.Repeat("x", shadowLeaseFileLimit+1))); err == nil {
		t.Fatal("oversized cache wrote")
	}
	if persisted, err := os.ReadFile(file); err != nil || string(persisted) != string(wire) {
		t.Fatal("failed write damaged previous cache")
	}
	if err := writeShadowLeaseFile(file, wire); err != nil {
		t.Fatal("atomic replacement failed", err)
	}
	entries, _ := os.ReadDir(filepath.Dir(file))
	if len(entries) != 1 {
		t.Fatal("temporary cache file leaked", entries)
	}
	link := filepath.Join(filepath.Dir(file), "link")
	if err := os.Symlink(file, link); err == nil {
		if _, err := readShadowLeaseFile(link, clock); err == nil {
			t.Fatal("cache symlink accepted")
		}
	}
}

func TestShadowLeaseStoreRestartAndUnchangedLeaseAvoidsWrites(t *testing.T) {
	clock, err := readShadowBootClock()
	if err != nil {
		t.Skip("kernel boot clock unavailable")
	}
	_, _, fixtures := shadowStoredFixture(t)
	lease := fixtures["ISP"]
	lease.expires = clock.now.Add(time.Hour)
	a := New(nil, nil)
	a.cfg.DataDir = t.TempDir()
	a.shadow.leases = map[string]shadowRememberedLease{"ISP": lease}
	a.shadow.leasesLoaded = true
	a.saveShadowLeases()
	filename := filepath.Join(a.cfg.DataDir, shadowLeaseFile)
	before, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	a.saveShadowLeases()
	after, err := os.ReadFile(filename)
	if err != nil || string(before) != string(after) {
		t.Fatal("unchanged lease rewrote saved_at/expiry", err)
	}
	b := New(nil, nil)
	b.cfg.DataDir = a.cfg.DataDir
	b.loadShadowLeases()
	restored, ok := b.shadow.leases["ISP"]
	// The serialized expiry has no monotonic component. A reload attaches a
	// new monotonic anchor to the same wall instant; comparing those anchors
	// during NTP clock slewing can falsely report a nanosecond extension.
	if !ok || !sameShadowLease(restored, lease) || restored.expires.Round(0).After(lease.expires.Round(0)) {
		t.Fatalf("restart did not preserve bounded lease: %+v", b.shadow.leases)
	}
	b.saveShadowLeases()
	after, err = os.ReadFile(filename)
	if err != nil || string(before) != string(after) {
		t.Fatal("reading lease after restart caused flash write", err)
	}
}

func TestShadowInformTargetPersistenceIsIndependentOfDNSLease(t *testing.T) {
	_, clock, leases := shadowStoredFixture(t)
	targets := map[string]shadowDHCPTarget{"ISP": {wanKey: leases["ISP"].wanKey, clientIP: leases["ISP"].clientIP, serverIP: net.ParseIP("192.168.0.1"), stamp: "Oct  3 11:00:00"}}
	wire, err := encodeShadowState(leases, targets, clock)
	if err != nil {
		t.Fatal(err)
	}
	later := clock
	later.now, later.uptime = clock.now.Add(2*time.Hour), clock.uptime+2*time.Hour
	got, retained, err := decodeShadowState(wire, later)
	if err != nil || len(got) != 0 || len(retained) != 1 || !retained["ISP"].serverIP.Equal(net.ParseIP("192.168.0.1")) {
		t.Fatal("DNS lease expiry removed the independently verified DHCP target", got, retained, err)
	}
	for _, mutate := range []func(*shadowLeaseDocument){
		func(d *shadowLeaseDocument) { d.BootID = "11234567-89ab-cdef-0123-456789abcdef" },
		func(d *shadowLeaseDocument) { d.DHCPTargets[0].ServerIP = "127.0.0.1" },
		func(d *shadowLeaseDocument) { d.DHCPTargets[0].ServerIP = d.DHCPTargets[0].ClientIP },
		func(d *shadowLeaseDocument) { d.DHCPTargets[0].Interface = "ISP;reboot" },
		func(d *shadowLeaseDocument) { d.DHCPTargets[0].Stamp = "invalid" },
		func(d *shadowLeaseDocument) { d.DHCPTargets = append(d.DHCPTargets, d.DHCPTargets[0]) },
	} {
		var doc shadowLeaseDocument
		if err := json.Unmarshal(wire, &doc); err != nil {
			t.Fatal(err)
		}
		mutate(&doc)
		bad, _ := json.Marshal(doc)
		if _, _, err := decodeShadowState(bad, later); err == nil {
			t.Fatal("invalid/unbound DHCP target accepted")
		}
	}
}

func TestShadowDiscoveredPeerPersistsWithoutInventingLease(t *testing.T) {
	_, clock, leases := shadowStoredFixture(t)
	targets := map[string]shadowDHCPTarget{"ISP": {wanKey: leases["ISP"].wanKey, clientIP: leases["ISP"].clientIP, serverIP: net.ParseIP("192.168.0.1")}}
	wire, err := encodeShadowState(nil, targets, clock)
	if err != nil {
		t.Fatal(err)
	}
	gotLeases, gotTargets, err := decodeShadowState(wire, clock)
	if err != nil || len(gotLeases) != 0 || len(gotTargets) != 1 || gotTargets["ISP"].stamp != "" || !gotTargets["ISP"].serverIP.Equal(targets["ISP"].serverIP) {
		t.Fatal("live discovered DHCP peer required historical lease evidence", gotLeases, gotTargets, err)
	}
	otherBoot := clock
	otherBoot.bootID = "11234567-89ab-cdef-0123-456789abcdef"
	if _, _, err := decodeShadowState(wire, otherBoot); err == nil {
		t.Fatal("peer discovery survived an unverified new boot")
	}
}
