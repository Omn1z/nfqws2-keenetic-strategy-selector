package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"nfqws2strategy/internal/services/awgroute"
	"nfqws2strategy/internal/services/dnsserver"
)

func dnsImportTestDocument(t *testing.T) dnsServerSettingsExport {
	t.Helper()
	cfg := dnsserver.Default()
	if err := cfg.NormalizeValidate(); err != nil {
		t.Fatal(err)
	}
	return dnsServerSettingsExport{Format: dnsServerExportFormat, Version: 1, ExportedAt: time.Date(2026, 10, 3, 1, 0, 0, 0, time.UTC), Config: cfg}
}
func dnsImportWire(t *testing.T, v any) []byte {
	t.Helper()
	wire, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
func dnsImportPublicRef(id, endpoint string) awgroute.AWG2ConnectionRef {
	ref := awgroute.AWG2ConnectionRef{Ref: id, Label: id, Endpoint: endpoint, ClientIface: "awg0", Protocol: "awg/2", ServerPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32))}
	hash := sha256.Sum256([]byte(ref.Protocol + "\x00" + ref.Endpoint + "\x00" + ref.ServerPublicKey + "\x00" + ref.ClientIface))
	ref.Fingerprint = hex.EncodeToString(hash[:16])
	return ref
}
func TestDNSImportVersionedDocumentRoundTripAndLegacyScheduler(t *testing.T) {
	doc := dnsImportTestDocument(t)
	doc.Config.SchedulerEnabled = false
	doc.Config.ShadowDNS.Enabled = true
	doc.Config.ShadowDNS.Servers = []string{"192.0.2.53:53"}
	doc.Config.LoggingEnabled = false
	doc.Config.FastDNS = false
	doc.Config.DNSPort = 5356
	doc.Config.Filtering.CustomRules = []dnsserver.BlockingRule{{Domain: "ads.example", Category: "ads"}}
	wire := dnsImportWire(t, doc)
	// Legacy exports may contain manual Shadow addresses; the imported
	// strategy always discovers the new router's own provider DNS.
	doc.Config.ShadowDNS.Servers = []string{}
	decoded, err := decodeDNSImportDocument(wire)
	if err != nil || !reflect.DeepEqual(decoded, doc) {
		t.Fatalf("complete export/import mismatch: %v %+v", err, decoded)
	}
	text := dnsImportWire(t, string(wire))
	decoded, err = decodeDNSImportDocument(text)
	if err != nil || !reflect.DeepEqual(decoded, doc) {
		t.Fatalf("string document=%+v %v", decoded, err)
	}
	if _, err := decodeDNSImportDocument(dnsImportWire(t, "\ufeff"+string(wire))); err != nil {
		t.Fatalf("UTF-8 BOM file rejected: %v", err)
	}
	var old map[string]any
	json.Unmarshal(wire, &old)
	delete(old["config"].(map[string]any), "scheduler_enabled")
	delete(old["config"].(map[string]any), "shadow_dns")
	decoded, err = decodeDNSImportDocument(dnsImportWire(t, old))
	if err != nil || !decoded.Config.SchedulerEnabled {
		t.Fatalf("legacy scheduler default=%v %v", decoded.Config.SchedulerEnabled, err)
	}
	if decoded.Config.ShadowDNS == nil || decoded.Config.ShadowDNS.Enabled {
		t.Fatal("legacy export enabled Shadow DNS")
	}
}
func TestDNSImportRejectsIncompleteUnknownNullAndWrongSchemas(t *testing.T) {
	doc := dnsImportTestDocument(t)
	wire := dnsImportWire(t, doc)
	for _, tc := range []struct {
		name   string
		modify func(map[string]any)
	}{
		{"wrong version", func(m map[string]any) { m["version"] = 2 }},
		{"wrong format", func(m map[string]any) { m["format"] = "routing" }},
		{"null config", func(m map[string]any) { m["config"] = nil }},
		{"missing enabled", func(m map[string]any) { delete(m["config"].(map[string]any), "enabled") }},
		{"null enabled", func(m map[string]any) { m["config"].(map[string]any)["enabled"] = nil }},
		{"null scheduler", func(m map[string]any) { m["config"].(map[string]any)["scheduler_enabled"] = nil }},
		{"unknown nested", func(m map[string]any) { m["config"].(map[string]any)["private_key"] = "secret" }},
		{"capitalized key", func(m map[string]any) { m["Config"] = m["config"]; delete(m, "config") }},
		{"case duplicate", func(m map[string]any) { m["Config"] = m["config"] }},
		{"null upstream", func(m map[string]any) { m["config"].(map[string]any)["default_upstream"] = nil }},
		{"missing rule enabled", func(m map[string]any) {
			delete(m["config"].(map[string]any)["rules"].([]any)[0].(map[string]any), "enabled")
		}},
		{"invalid listener", func(m map[string]any) { m["config"].(map[string]any)["listen_host"] = "0.0.0.0" }},
		{"invalid provider", func(m map[string]any) {
			m["config"].(map[string]any)["default_upstream"].(map[string]any)["address"] = "http://1.1.1.1"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var m map[string]any
			json.Unmarshal(wire, &m)
			tc.modify(m)
			if _, err := decodeDNSImportDocument(dnsImportWire(t, m)); err == nil {
				t.Fatal("malformed document accepted")
			}
		})
	}
	for _, bad := range []string{`{"format":"a","format":"b"}`, string(wire) + ` {}`, "{", `null`} {
		if _, err := decodeDNSImportDocument([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	if _, err := decodeDNSImportDocument([]byte(strings.Repeat(" ", dnsImportDocumentLimit+1))); !errors.Is(err, errDNSImportSize) {
		t.Fatalf("document cap=%v", err)
	}
}
func TestDNSImportInvalidHTTPRequestNeverTouchesApp(t *testing.T) {
	// A nil App makes any premature read or write fail. Both handlers must fully
	// validate malformed envelopes and documents before observing live services.
	for _, path := range []string{"/api/dnsserver/import/preview", "/api/dnsserver/import"} {
		for _, body := range []string{`{}`, `{"document":null}`, `{"document":"{}"}`, `{"document":{},"unknown":true}`, `{"document":{},"document":{}}`} {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			s := &Server{}
			if strings.HasSuffix(path, "preview") {
				s.dnsServerImportPreview(w, r)
			} else {
				s.dnsServerImport(w, r)
			}
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s code=%d body=%s", path, w.Code, w.Body.String())
			}
		}
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/dnsserver/import/preview", strings.NewReader(strings.Repeat(" ", dnsImportRequestLimit+1)))
	(&Server{}).dnsServerImportPreview(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("request cap=%d", w.Code)
	}
	doc := strings.Repeat(" ", dnsImportDocumentLimit+1)
	body := dnsImportWire(t, map[string]any{"document": doc})
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/api/dnsserver/import", strings.NewReader(string(body)))
	(&Server{}).dnsServerImport(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("document cap response=%d", w.Code)
	}
}
func TestDNSImportPortableVPNMatchesIdentityAndNeverSameID(t *testing.T) {
	doc := dnsImportTestDocument(t)
	source := dnsImportPublicRef("old", "198.51.100.1:51820")
	doc.Config.AWGFallback = source.Ref
	doc.Connections = []awgroute.AWG2ConnectionRef{source}
	doc.Config.DisabledMethods = []dnsserver.DisabledMethod{{Upstream: doc.Config.DefaultUpstream.Address, Route: "awg:old"}}
	same := source
	same.Ref = "new"
	same.Label = "renamed"
	changed := dnsImportPublicRef("old", "203.0.113.2:51820")
	plan, err := prepareDNSImport(doc, dnsImportRequest{}, []awgroute.AWG2ConnectionRef{changed, same})
	if err != nil || plan.VPN.State != "matched" || plan.VPN.MatchedID != "new" || plan.Config.AWGFallback != "new" || plan.Config.DisabledMethods[0].Route != "awg:new" {
		t.Fatalf("identity remap=%+v %v", plan, err)
	}
	plan, err = prepareDNSImport(doc, dnsImportRequest{}, []awgroute.AWG2ConnectionRef{changed})
	if err != nil || plan.VPN.State != "missing" || len(plan.Config.DisabledMethods) != 0 || len(plan.Warnings) == 0 {
		t.Fatalf("same ID reused wrong identity: %+v %v", plan, err)
	}
	doc.Connections = nil
	plan, err = prepareDNSImport(doc, dnsImportRequest{}, []awgroute.AWG2ConnectionRef{source})
	if err != nil || plan.VPN.State != "selection_required" || plan.VPN.MatchedID != "" {
		t.Fatalf("legacy ID auto assigned: %+v %v", plan, err)
	}
	doc.Connections = []awgroute.AWG2ConnectionRef{source}
	duplicate := same
	duplicate.Ref = "another"
	plan, err = prepareDNSImport(doc, dnsImportRequest{}, []awgroute.AWG2ConnectionRef{same, duplicate})
	if err != nil || plan.VPN.State != "ambiguous" || plan.VPN.MatchedID != "" {
		t.Fatalf("ambiguous identity auto assigned: %+v %v", plan, err)
	}
}
func TestDNSImportManualVPNRequiresCurrentFingerprintAndPreservesNFQWS(t *testing.T) {
	doc := dnsImportTestDocument(t)
	doc.Config.AWGFallback = "foreign"
	target := dnsImportPublicRef("local", "203.0.113.1:51820")
	doc.Config.DisabledMethods = []dnsserver.DisabledMethod{{Upstream: doc.Config.DefaultUpstream.Address, Route: "nfqws"}, {Upstream: doc.Config.DefaultUpstream.Address, Route: "awg:foreign"}, {Upstream: doc.Config.DefaultUpstream.Address, Route: "awg:unknown"}}
	before := dnsImportWire(t, doc)
	for _, fp := range []string{"", strings.Repeat("0", 32)} {
		if _, err := prepareDNSImport(doc, dnsImportRequest{Mapping: ptrString("local"), MappingFingerprint: fp}, []awgroute.AWG2ConnectionRef{target}); err == nil {
			t.Fatal("unconfirmed changed target accepted")
		}
	}
	plan, err := prepareDNSImport(doc, dnsImportRequest{Mapping: ptrString("local"), MappingFingerprint: target.Fingerprint}, []awgroute.AWG2ConnectionRef{target})
	if err != nil || plan.Config.AWGFallback != "local" || plan.VPN.MatchedID != "local" || len(plan.Config.DisabledMethods) != 2 || plan.Config.DisabledMethods[0].Route != "nfqws" || plan.Config.DisabledMethods[1].Route != "awg:local" {
		t.Fatalf("manual mapping=%+v %v", plan, err)
	}
	if string(dnsImportWire(t, doc)) != string(before) {
		t.Fatal("mapping/preview mutated source document")
	}
}
func TestDNSExportIncludesOnlyReferencedPublicIdentities(t *testing.T) {
	doc := dnsImportTestDocument(t)
	doc.Config.AWGFallback = "primary"
	doc.Config.DisabledMethods = []dnsserver.DisabledMethod{{Upstream: doc.Config.DefaultUpstream.Address, Route: "awg:missing"}, {Upstream: doc.Config.DefaultUpstream.Address, Route: "nfqws"}}
	primary := dnsImportPublicRef("primary", "203.0.113.1:51820")
	unused := dnsImportPublicRef("unused", "203.0.113.2:51820")
	refs := dnsExportConnections(doc.Config, []awgroute.AWG2ConnectionRef{unused, primary})
	if len(refs) != 2 || refs[0].Ref != "missing" || refs[0].Fingerprint != "" || refs[1].Ref != "primary" {
		t.Fatalf("wrong referenced metadata %+v", refs)
	}
	w := httptest.NewRecorder()
	writeDNSServerSettingsExport(w, doc.Config, doc.ExportedAt, refs)
	restored, err := decodeDNSImportDocument(w.Body.Bytes())
	if err != nil || !reflect.DeepEqual(restored.Connections, refs) {
		t.Fatalf("metadata roundtrip=%+v %v", restored, err)
	}
	for _, secret := range []string{"private_key", "preshared_key", "password", "stats", "logs"} {
		if strings.Contains(w.Body.String(), `"`+secret+`"`) {
			t.Fatalf("export leaked %s", secret)
		}
	}
	forged := primary
	forged.Fingerprint = strings.Repeat("0", 32)
	doc.Connections = []awgroute.AWG2ConnectionRef{forged}
	if _, err := decodeDNSImportDocument(dnsImportWire(t, doc)); err == nil {
		t.Fatal("forged fingerprint accepted")
	}
}
func TestDNSImportRoutesProtectedAndConflictResponse(t *testing.T) {
	s := New(nil)
	for _, path := range []string{"/api/dnsserver/import/preview", "/api/dnsserver/import"} {
		if publicAPI(path) {
			t.Fatalf("unprotected import %s", path)
		}
		_, pattern := s.mux.Handler(httptest.NewRequest(http.MethodPost, path, nil))
		if pattern != "POST "+path {
			t.Fatalf("route missing %q", pattern)
		}
	}
	w := httptest.NewRecorder()
	dnsImportError(w, dnsserver.ErrImportConfigConflict)
	if w.Code != http.StatusConflict {
		t.Fatalf("CAS failure code %d", w.Code)
	}
}

func TestDNSExportLargeCompleteConfigRemainsImportable(t *testing.T) {
	doc := dnsImportTestDocument(t)
	doc.Config.Rules = nil
	for i := 0; i < 512; i++ {
		upstream := dnsserver.Upstream{Address: "https://example.com/" + strings.Repeat("a", 1800), BootstrapIPs: []string{}}
		doc.Config.Rules = append(doc.Config.Rules, dnsserver.Rule{ID: strconv.Itoa(i), Domain: fmt.Sprintf("d%d.example", i), Upstream: upstream, Pool: []dnsserver.Upstream{{Address: upstream.Address + "b", BootstrapIPs: []string{}}, {Address: upstream.Address + "c", BootstrapIPs: []string{}}}})
	}
	if err := doc.Config.NormalizeValidate(); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	writeDNSServerSettingsExport(w, doc.Config, doc.ExportedAt)
	if w.Code != http.StatusOK || len(w.Body.Bytes()) <= 2<<20 {
		t.Fatalf("valid large config rejected: %d %d", w.Code, len(w.Body.Bytes()))
	}
	if _, err := decodeDNSImportDocument(w.Body.Bytes()); err != nil {
		t.Fatalf("large export cannot be imported: %v", err)
	}
	// The writer also guards an over-limit snapshot before download headers.
	doc.Config.Rules[0].Domain = strings.Repeat("a", dnsImportDocumentLimit)
	w = httptest.NewRecorder()
	writeDNSServerSettingsExport(w, doc.Config, doc.ExportedAt)
	if w.Code != http.StatusRequestEntityTooLarge || w.Header().Get("Content-Disposition") != "" {
		t.Fatalf("over-limit download: %d %v", w.Code, w.Header())
	}
}
