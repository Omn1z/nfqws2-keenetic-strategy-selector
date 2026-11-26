package awgroute

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"nfqws2strategy/internal/services/awg"
)

func portableReference(id, endpoint, iface string, keyByte byte) AWG2ConnectionRef {
	ref := AWG2ConnectionRef{Ref: id, Label: "label " + id, Endpoint: endpoint, ClientIface: iface, Protocol: "awg/3.1", ServerPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{keyByte}, 32))}
	ref.Fingerprint = awgConnectionFingerprint(ref)
	return ref
}

func portableDocument(refs ...AWG2ConnectionRef) AWGRoutingDocument {
	on := true
	rules := []awg.Zone{}
	for i, ref := range refs {
		rules = append(rules, awg.Zone{Name: "rule " + ref.Ref, TunnelID: ref.Ref, Order: i + 1, Route: "tunnel", Mode: "include", Domains: []string{"example.org", "[re]^video\\."}, IncludeSubdomains: &on, IPs: []string{"203.0.113.9/32", "2001:db8::/32"}, SourceIPs: []string{"192.168.3.10/32"}, Enabled: true})
	}
	return AWGRoutingDocument{Format: awgRoutingFormat, Version: 1, Routing: awg.RoutingConfig{Mode: "zones", DomainSource: "dnsproxy", MTU: 1420, Killswitch: true, SNIRouting: true, TraceEnabled: true, Zones: rules}, Connections: refs}
}

func routingRaw(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRoutingConnectionFingerprintCanonicalIdentityAndNoSecrets(t *testing.T) {
	ref := portableReference("old-id", "VPN.Example.:00443", "awg1", 1)
	canonical := ref
	canonical.Ref = "new-id"
	canonical.Label = "renamed"
	canonical.Endpoint = "vpn.example:443"
	if ref.Fingerprint == "" || awgConnectionFingerprint(canonical) != ref.Fingerprint {
		t.Fatal("normalization, local ID or label changed public identity")
	}
	for _, mutate := range []func(*AWG2ConnectionRef){func(r *AWG2ConnectionRef) { r.ClientIface = "awg2" }, func(r *AWG2ConnectionRef) { r.Endpoint = "vpn.example:444" }, func(r *AWG2ConnectionRef) { r.Protocol = "awg/2" }, func(r *AWG2ConnectionRef) {
		r.ServerPublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	}} {
		changed := canonical
		mutate(&changed)
		if awgConnectionFingerprint(changed) == ref.Fingerprint {
			t.Fatal("changed public parameters retained identity")
		}
	}
	for _, mutate := range []func(*AWG2ConnectionRef){func(r *AWG2ConnectionRef) { r.Endpoint = "" }, func(r *AWG2ConnectionRef) { r.ClientIface = "" }, func(r *AWG2ConnectionRef) { r.Protocol = "" }, func(r *AWG2ConnectionRef) { r.ServerPublicKey = "" }} {
		missing := canonical
		mutate(&missing)
		if awgConnectionFingerprint(missing) != "" {
			t.Fatal("incomplete profile auto-matches")
		}
	}
	svc := pendingRuleFixture(t, "source")
	cfg := svc.servers["source"].Manager.Config()
	cfg.PublicKey = canonical.ServerPublicKey
	svc.servers["source"].Manager.SetConfig(&cfg)
	encoded := string(routingRaw(t, awgConnectionReference(svc.servers["source"])))
	for _, secret := range []string{"private_key", "password", "key_pem", "psk", "secret-"} {
		if strings.Contains(encoded, secret) {
			t.Fatal("public descriptor exported a secret")
		}
	}
}

func TestRoutingPreviewNeverTrustsIDAndOffersAllTargets(t *testing.T) {
	source := portableReference("same", "vpn.example:443", "awg0", 1)
	changed := portableReference("same", "other.example:443", "awg0", 2)
	equal := source
	equal.Ref = "different"
	other := portableReference("other", "third.example:443", "awg2", 3)
	plan := awgRoutingPreview(portableDocument(source), map[string]AWG2ConnectionRef{"same": changed, "different": equal, "other": other, "blank": {Ref: "blank"}})
	item := plan.Connections[0]
	if item.State != "matched" || item.MatchedTunnelID != "different" || item.Reason != "" || len(item.Candidates) != 3 {
		t.Fatalf("wrong plan: %+v", item)
	}
	duplicate := equal
	duplicate.Ref = "duplicate"
	plan = awgRoutingPreview(portableDocument(source), map[string]AWG2ConnectionRef{"different": equal, "duplicate": duplicate})
	if plan.Connections[0].State != "ambiguous" || plan.Connections[0].MatchedTunnelID != "" {
		t.Fatal("collision silently chose a target")
	}
	plan = awgRoutingPreview(portableDocument(source), map[string]AWG2ConnectionRef{"same": changed})
	if plan.Connections[0].State != "missing" || plan.Connections[0].Reason != "identity_changed" {
		t.Fatal("same ID matched a different server")
	}
}

func TestRoutingImportRemapsAllParametersFallbacksAndDraftAppend(t *testing.T) {
	source := portableReference("primary", "one.example:443", "awg0", 1)
	backup := portableReference("backup", "two.example:443", "awg1", 2)
	doc := portableDocument(source, backup)
	doc.Routing.Zones[0].FallbackTunnelIDs = []string{"backup"}
	off := false
	doc.Routing.Zones[1].IncludeSubdomains = &off
	doc.Routing.Zones[1].Enabled = false
	primary := source
	primary.Ref = "local-primary"
	localBackup := backup
	localBackup.Ref = "local-backup"
	live := map[string]AWG2ConnectionRef{primary.Ref: primary, localBackup.Ref: localBackup}
	rc, _, err := awgPrepareRoutingImport(doc, AWGRoutingImportRequest{Mode: "replace"}, live, nil, awg.RoutingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	want := doc.Routing
	want.Zones = cloneAWGZones(doc.Routing.Zones)
	want.Zones[0].TunnelID = primary.Ref
	want.Zones[0].FallbackTunnelIDs = []string{localBackup.Ref}
	want.Zones[1].TunnelID = localBackup.Ref
	if !reflect.DeepEqual(rc, want) {
		t.Fatalf("remap changed other rule parameters: %+v", rc)
	}
	base := awg.RoutingConfig{Mode: "off", DomainSource: "resolve", MTU: 1300, Zones: []awg.Zone{{Name: "unsaved draft", TunnelID: primary.Ref, Route: "direct", Domains: []string{"draft.example"}, Enabled: true}}}
	rc, _, err = awgPrepareRoutingImport(doc, AWGRoutingImportRequest{Mode: "append", BaseRouting: &base}, live, nil, awg.RoutingConfig{})
	if err != nil || len(rc.Zones) != 3 || rc.Zones[0].Name != "unsaved draft" || rc.Mode != "off" || rc.MTU != 1300 || rc.Zones[2].Order != 3 {
		t.Fatalf("append discarded visible draft: %+v %v", rc, err)
	}
	if len(base.Zones) != 1 || doc.Routing.Zones[0].TunnelID != "primary" {
		t.Fatal("preparation mutated its inputs")
	}
}

func TestRoutingImportManualIdentityRecheckAndMissingChoice(t *testing.T) {
	source := portableReference("source", "one.example:443", "awg0", 1)
	target := source
	target.Ref = "target"
	target.ClientIface = "awg5"
	target.Fingerprint = awgConnectionFingerprint(target)
	doc := portableDocument(source)
	live := map[string]AWG2ConnectionRef{target.Ref: target}
	if _, _, err := awgPrepareRoutingImport(doc, AWGRoutingImportRequest{Mode: "replace"}, live, nil, awg.RoutingConfig{}); err == nil {
		t.Fatal("missing mapping implicitly chose a default")
	}
	req := AWGRoutingImportRequest{Mode: "replace", Mappings: map[string]string{source.Ref: target.Ref}}
	if _, _, err := awgPrepareRoutingImport(doc, req, live, nil, awg.RoutingConfig{}); err == nil {
		t.Fatal("manual change lacked a confirmed target identity")
	}
	req.MappingFingerprints = map[string]string{source.Ref: target.Fingerprint}
	if _, _, err := awgPrepareRoutingImport(doc, req, live, nil, awg.RoutingConfig{}); err != nil {
		t.Fatal(err)
	}
	changed := target
	changed.Endpoint = "changed.example:443"
	changed.Fingerprint = awgConnectionFingerprint(changed)
	live[target.Ref] = changed
	if _, _, err := awgPrepareRoutingImport(doc, req, live, nil, awg.RoutingConfig{}); err == nil {
		t.Fatal("stale preview overwrote a changed target")
	}
}

func TestRoutingWaitSameIDChangedServerSurvivesReloadAndReexport(t *testing.T) {
	svc := pendingRuleFixture(t, "same")
	cfg := svc.servers["same"].Manager.Config()
	cfg.PublicKey = portableReference("same", "x.example:443", "awg0", 2).ServerPublicKey
	svc.servers["same"].Manager.SetConfig(&cfg)
	source := portableReference("same", "old.example:443", "awg0", 1)
	doc := portableDocument(source)
	live := awgRoutingLiveReferences(svc.serverSnapshot())
	rc, refs, err := awgPrepareRoutingImport(doc, AWGRoutingImportRequest{Mode: "replace", Mappings: map[string]string{"same": ""}}, live, svc.connectionRefSnapshot(), awg.RoutingConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if rc.Zones[0].TunnelID == "same" || !rc.Zones[0].WaitingForConnection {
		t.Fatal("wait reused the live ID")
	}
	_, unlock := svc.lockClientOps(false)
	err = svc.awgSaveRoutingRulesWithRefs(rc, refs)
	unlock()
	if err != nil {
		t.Fatal(err)
	}
	reloaded := reloadPendingRuleFixture(svc)
	exported, err := reloaded.AWG2ExportRoutingRules(nil)
	if err != nil {
		t.Fatal(err)
	}
	if exported.Connections[0].Fingerprint != source.Fingerprint || !exported.Routing.Zones[0].WaitingForConnection {
		t.Fatal("reexport lost detached old identity")
	}
	plan, err := reloaded.AWG2PreviewRoutingRules(routingRaw(t, exported))
	if err != nil || plan.Connections[0].State != "missing" {
		t.Fatalf("waiting source attached to changed server after reload: %+v %v", plan, err)
	}
	// Same transfer retry keeps the exact detached ID and candidate hash.
	again, againRefs, err := awgPrepareRoutingImport(doc, AWGRoutingImportRequest{Mode: "replace", Mappings: map[string]string{"same": ""}}, live, reloaded.connectionRefSnapshot(), awg.RoutingConfig{})
	if err != nil || again.Zones[0].TunnelID != rc.Zones[0].TunnelID || !reflect.DeepEqual(refs, againRefs) {
		t.Fatal("retry produced a second pending identity")
	}
}

func TestRoutingImportCASPreventsDuplicateAppendAndConcurrentEdits(t *testing.T) {
	ref := portableReference("one", "vpn.example:443", "awg0", 1)
	refs := map[string]AWG2ConnectionRef{ref.Ref: ref}
	base := portableDocument(ref).Routing
	doc := portableDocument(ref)
	req := AWGRoutingImportRequest{Mode: "append", BaseRouting: &base}
	candidate, _, err := awgPrepareRoutingImport(doc, req, refs, nil, base)
	if err != nil {
		t.Fatal(err)
	}
	expected := awgRoutingPolicyHash(base, refs)
	applied := awgRoutingPolicyHash(candidate, refs)
	if already, err := awgRoutingImportAllowed(expected, expected, applied); err != nil || already {
		t.Fatal("initial import rejected")
	}
	if already, err := awgRoutingImportAllowed(expected, applied, applied); err != nil || !already {
		t.Fatal("ACK-lost retry would append twice")
	}
	changed := base
	changed.Killswitch = false
	if _, err := awgRoutingImportAllowed(expected, awgRoutingPolicyHash(changed, refs), applied); !errors.Is(err, ErrAWGRoutingPolicyConflict) {
		t.Fatal("unrelated edit was overwritten")
	}
	if _, err := awgRoutingImportAllowed("", expected, applied); err == nil {
		t.Fatal("import had no policy comparison")
	}
	rename := ref
	rename.Label = "new label"
	if awgRoutingPolicyHash(base, map[string]AWG2ConnectionRef{ref.Ref: rename}) != expected {
		t.Fatal("rename caused unnecessary conflict")
	}
	identity := ref
	identity.ClientIface = "awg9"
	identity.Fingerprint = awgConnectionFingerprint(identity)
	if awgRoutingPolicyHash(base, map[string]AWG2ConnectionRef{ref.Ref: identity}) == expected {
		t.Fatal("changed live identity was absent from policy hash")
	}
}

func TestRoutingDocumentValidationStrictAndTransactional(t *testing.T) {
	ref := portableReference("one", "vpn.example:443", "awg0", 1)
	doc := portableDocument(ref)
	raw := routingRaw(t, doc)
	if _, err := awgDecodeRoutingDocument(routingRaw(t, string(raw))); err != nil {
		t.Fatal("raw-string document rejected", err)
	}
	cases := map[string][]byte{
		"duplicate key":        []byte(strings.Replace(string(raw), `"version":1`, `"version":1,"version":1`, 1)),
		"unknown secret":       []byte(strings.Replace(string(raw), `"format":`, `"private_key":"secret","format":`, 1)),
		"version":              []byte(strings.Replace(string(raw), `"version":1`, `"version":2`, 1)),
		"trailing":             append(append([]byte(nil), raw...), []byte("{}")...),
		"oversize":             bytes.Repeat([]byte(" "), AWGRoutingDocumentLimit+1),
		"duplicate descriptor": routingRaw(t, func() AWGRoutingDocument { v := doc; v.Connections = append(v.Connections, ref); return v }()),
		"fingerprint": routingRaw(t, func() AWGRoutingDocument {
			v := doc
			v.Connections = append([]AWG2ConnectionRef(nil), doc.Connections...)
			v.Connections[0].Fingerprint = "00000000000000000000000000000000"
			return v
		}()),
		"IP injection": routingRaw(t, func() AWGRoutingDocument {
			v := doc
			v.Routing.Zones = cloneAWGZones(doc.Routing.Zones)
			v.Routing.Zones[0].IPs = []string{"1.2.3.4; touch /tmp/test"}
			return v
		}()),
		"domain injection": routingRaw(t, func() AWGRoutingDocument {
			v := doc
			v.Routing.Zones = cloneAWGZones(doc.Routing.Zones)
			v.Routing.Zones[0].Domains = []string{"example.org;touch /tmp/test"}
			return v
		}()),
		"missing descriptor": routingRaw(t, func() AWGRoutingDocument { v := doc; v.Connections = nil; return v }()),
		"null routing":       []byte(`{"format":"nfqws2-strategy-routing","version":1,"routing":null,"connections":[]}`),
		"missing zones":      []byte(`{"format":"nfqws2-strategy-routing","version":1,"routing":{},"connections":[]}`),
		"dependency": routingRaw(t, func() AWGRoutingDocument {
			v := doc
			v.Routing.Zones = cloneAWGZones(doc.Routing.Zones)
			v.Routing.Zones[0].Domains = []string{"list:missing"}
			return v
		}()),
	}
	svc := pendingRuleFixture(t, "one")
	svc.awgSaveErr()
	before, err := os.ReadFile(svc.store.Path(awgConfigFile))
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := svc.AWG2ImportRoutingRules(AWGRoutingImportRequest{Document: bad, Mode: "replace"}); err == nil {
				t.Fatal("invalid document accepted")
			}
			after, err := os.ReadFile(svc.store.Path(awgConfigFile))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("invalid import changed persisted state")
			}
		})
	}
}

func TestRoutingSnapshotDependenciesPortableAndNoSourceMutation(t *testing.T) {
	ref := portableReference("one", "vpn.example:443", "awg0", 1)
	rc := portableDocument(ref).Routing
	rc.Zones[0].Domains = []string{"exact.example", "list:sites", "geosite:category", "geoip:country"}
	off := false
	rc.Zones[0].IncludeSubdomains = &off
	original := cloneAWGZones(rc.Zones)
	exported, warnings, err := awgSnapshotRoutingDependencies(rc, func(kind, name string) ([]string, error) {
		switch kind {
		case "list":
			return []string{"child.example", "[re]^re\\.example$"}, nil
		case "geosite":
			return []string{"geo.example"}, nil
		case "geoip":
			return []string{"198.51.100.0/24", "2001:db8::/32"}, nil
		}
		return nil, errors.New("missing")
	})
	if err != nil || len(warnings) != 1 || len(exported.Zones[0].Domains) != 4 || len(exported.Zones[0].IPs) != 4 || exported.Zones[0].IncludeSubdomains == nil || *exported.Zones[0].IncludeSubdomains {
		t.Fatalf("bad snapshot: %+v %v", exported, err)
	}
	if !reflect.DeepEqual(rc.Zones, original) {
		t.Fatal("export mutated source rules")
	}
	if _, _, err := awgSnapshotRoutingDependencies(rc, func(string, string) ([]string, error) { return nil, errors.New("missing") }); err == nil {
		t.Fatal("missing dependency became an empty rule")
	}
	if _, _, err := awgSnapshotRoutingDependencies(rc, func(string, string) ([]string, error) { return []string{"list:nested"}, nil }); err == nil {
		t.Fatal("nested unresolved references survived export")
	}
	dir := t.TempDir()
	file, err := os.Create(filepath.Join(dir, "sites.list.gz"))
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	gz.Write([]byte("# comment\nexample.org\n203.0.113.0/24\n"))
	gz.Close()
	file.Close()
	entries, err := awgReadPortableList(dir, "sites")
	if err != nil || len(entries) != 2 {
		t.Fatal(entries, err)
	}
	if _, err := awgReadPortableList(dir, "../sites"); err == nil {
		t.Fatal("path traversal accepted")
	}
	if _, err := awgReadPortableList(dir, "missing"); err == nil {
		t.Fatal("missing list accepted")
	}
}

func TestRoutingWaitingCatchAllDoesNotShadowOrLearn(t *testing.T) {
	r := awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{{Name: "waiting all", WaitingForConnection: true, Enabled: true, Route: "direct", Domains: []string{"*"}}, {Name: "live", Enabled: true, Route: "tunnel", Domains: []string{"live.example"}}, {Name: "waiting source", WaitingForConnection: true, Enabled: true, Route: "tunnel", SourceIPs: []string{"192.168.3.10"}, Domains: []string{"*"}}}}
	if firstCatchAllZoneIndex(r) != -1 || len(effectiveZones(r)) != 1 || len(sourceBoundZones(r.Zones)) != 0 || awgEffectiveMode(r) != "include" {
		t.Fatal("waiting rule affected active policy")
	}
	svc := &Service{}
	cfg := &awg.ServerConfig{Routing: r}
	table := svc.buildRouteTable(cfg, false)
	if len(table.ordered) != 1 || len(table.source) != 0 {
		t.Fatal("waiting rule became a DNS learner")
	}
	hash := routeTableInputHash(cfg, false)
	cfg.Routing.Zones[0].WaitingForConnection = false
	if hash == routeTableInputHash(cfg, false) {
		t.Fatal("waiting status absent from route cache identity")
	}
}

func TestRoutingBlankWaitingExportCannotSelectActiveConnection(t *testing.T) {
	svc := pendingRuleFixture(t, "active")
	cfg := svc.servers["active"].Manager.Config()
	cfg.PublicKey = portableReference("active", "vpn.example:443", "awg0", 1).ServerPublicKey
	svc.servers["active"].Manager.SetConfig(&cfg)
	draft := svc.globalRoutingConfig([]awg.Zone{{Name: "unassigned", WaitingForConnection: true, Domains: []string{"*"}, Enabled: true}})
	exported, err := svc.AWG2ExportRoutingRules(&draft)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(exported.Routing.Zones[0].TunnelID, "pending-unassigned-") || exported.Connections[0].Fingerprint != "" {
		t.Fatal("waiting rule inherited the selected live identity")
	}
	plan, err := svc.AWG2PreviewRoutingRules(routingRaw(t, exported))
	if err != nil || plan.Connections[0].State != "missing" {
		t.Fatal("unassigned waiting rule auto-matched", err)
	}
}

func TestRoutingWaitingKeepsOriginalPriorityAgainstSourceRules(t *testing.T) {
	r := awg.RoutingConfig{Mode: "zones", Zones: []awg.Zone{{WaitingForConnection: true, Enabled: true, Domains: []string{"*"}}, {Enabled: true, Route: "direct", SourceIPs: []string{"192.168.3.10"}, Domains: []string{"*"}}, {Enabled: true, Route: "tunnel", Domains: []string{"example.org"}}}}
	svc := &Service{}
	svc.route.routeTable.Store(svc.buildRouteTable(&awg.ServerConfig{Routing: r}, false))
	decision := svc.routeFor("example.org", "192.168.3.10")
	if decision.Route != RouteDirect || !decision.SourceBound || decision.RuleIdx != 2 {
		t.Fatalf("filtered waiting rule reordered the merge: %+v", decision)
	}
}

func TestRoutingImportEndToEndSavedRetryAndConflict(t *testing.T) {
	svc := pendingRuleFixture(t, "target")
	cfg := svc.servers["target"].Manager.Config()
	cfg.PublicKey = portableReference("target", "vpn.example:443", "awg0", 1).ServerPublicKey
	svc.servers["target"].Manager.SetConfig(&cfg)
	target := awgConnectionReference(svc.servers["target"])
	source := target
	source.Ref = "source"
	doc := portableDocument(source)
	base := svc.globalRoutingConfig([]awg.Zone{{Name: "visible draft", TunnelID: target.Ref, Route: "direct", Domains: []string{"draft.example"}, Enabled: true}})
	plan, err := svc.AWG2PreviewRoutingRules(routingRaw(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	request := AWGRoutingImportRequest{Document: routingRaw(t, doc), Mode: "append", BaseRouting: &base, ExpectedPolicyHash: plan.PolicyHash}
	applies := 0
	apply := func() error { applies++; return nil }
	first, err := svc.awgImportRoutingRulesWithApply(request, apply)
	if err != nil {
		t.Fatal(err)
	}
	if first.RuleCount != 2 || first.Routing.Zones[0].Name != "visible draft" || applies != 1 {
		t.Fatal("first import lost draft or rules")
	}
	raw, err := os.ReadFile(svc.store.Path(awgConfigFile))
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.awgImportRoutingRulesWithApply(request, apply)
	if err != nil {
		t.Fatal("retry should succeed after a lost ACK", err)
	}
	after, err := os.ReadFile(svc.store.Path(awgConfigFile))
	if err != nil || !bytes.Equal(raw, after) || second.RuleCount != 2 || second.RoutingRevision != first.RoutingRevision || applies != 1 {
		t.Fatal("retry duplicated rules, persisted twice or re-applied healthy routing")
	}
	changed := first.Routing
	changed.Killswitch = !changed.Killswitch
	if err := svc.awgSaveRoutingRules(changed); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(svc.store.Path(awgConfigFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.awgImportRoutingRulesWithApply(request, apply); !errors.Is(err, ErrAWGRoutingPolicyConflict) {
		t.Fatal("retry overwrote unrelated policy edits", err)
	}
	after, err = os.ReadFile(svc.store.Path(awgConfigFile))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("conflict changed persistence")
	}
}

func TestRoutingSnapshotGeoMissingFilesAndBadMetadataFail(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "geo")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	meta := filepath.Join(filepath.Dir(dir), "geo_meta.json")
	if err := os.WriteFile(meta, []byte(`{"missing.dat":"geosite"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := awgReadPortableGeo(dir, "geosite", "youtube"); err == nil {
		t.Fatal("missing geo file silently omitted")
	}
	if err := os.WriteFile(meta, []byte(`{"bad.dat":"geosite","bad.dat":"geosite"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := awgReadPortableGeo(dir, "geosite", "youtube"); err == nil {
		t.Fatal("duplicate metadata keys accepted")
	}
	if err := os.WriteFile(meta, []byte(`{"../bad.dat":"geosite"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := awgReadPortableGeo(dir, "geosite", "youtube"); err == nil {
		t.Fatal("geo metadata path traversal accepted")
	}
}
