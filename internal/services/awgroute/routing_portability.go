package awgroute

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"nfqws2strategy/internal/services/awg"
)

const AWGRoutingDocumentLimit = 2 << 20
const AWGRoutingRequestLimit = 8 << 20
const awgRoutingFormat = "nfqws2-strategy-routing"
const awgRoutingMaxRules = 2048
const awgRoutingMaxEntries = 100000

type AWGRoutingDocument struct {
	Format      string              `json:"format"`
	Version     int                 `json:"version"`
	Routing     awg.RoutingConfig   `json:"routing"`
	Connections []AWG2ConnectionRef `json:"connections"`
	Warnings    []string            `json:"warnings,omitempty"`
}

type AWGRoutingCandidate struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Endpoint    string `json:"endpoint"`
	ClientIface string `json:"client_iface"`
	Protocol    string `json:"protocol"`
	Fingerprint string `json:"fingerprint"`
}

type AWGRoutingConnectionPlan struct {
	Source          AWG2ConnectionRef     `json:"source"`
	State           string                `json:"state"`
	MatchedTunnelID string                `json:"matched_tunnel_id,omitempty"`
	Candidates      []AWGRoutingCandidate `json:"candidates"`
	Reason          string                `json:"reason,omitempty"`
}

type AWGRoutingImportPlan struct {
	Connections      []AWGRoutingConnectionPlan `json:"connections"`
	RuleCount        int                        `json:"rule_count"`
	WaitingRuleCount int                        `json:"waiting_rule_count"`
	Warnings         []string                   `json:"warnings"`
	PolicyHash       string                     `json:"policy_hash"`
}

type AWGRoutingImportRequest struct {
	Document            json.RawMessage    `json:"document"`
	Mappings            map[string]string  `json:"mappings"`
	MappingFingerprints map[string]string  `json:"mapping_fingerprints,omitempty"`
	Mode                string             `json:"mode"`
	BaseRouting         *awg.RoutingConfig `json:"base_routing,omitempty"`
	ExpectedPolicyHash  string             `json:"expected_policy_hash"`
}

type AWGRoutingImportResult struct {
	RuleCount        int               `json:"rule_count"`
	WaitingRuleCount int               `json:"waiting_rule_count"`
	RoutingRevision  int64             `json:"routing_revision"`
	Routing          awg.RoutingConfig `json:"routing"`
}

// DecodeAWGRoutingJSON rejects duplicate keys before decoding into concrete
// structs. encoding/json alone silently accepts duplicate and unknown fields.
func DecodeAWGRoutingJSON(raw []byte, out any, limit int) error {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return fmt.Errorf("неверный JSON или превышен размер %d байт", limit)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := awgCheckJSONValue(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("JSON должен содержать один документ")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return fmt.Errorf("неверный JSON: %w", err)
	}
	return nil
}

func awgCheckJSONValue(d *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("слишком глубокий JSON")
	}
	t, err := d.Token()
	if err != nil {
		return fmt.Errorf("неверный JSON: %w", err)
	}
	delim, compound := t.(json.Delim)
	if !compound {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return fmt.Errorf("повторяющееся поле JSON: %v", key)
			}
			seen[name] = true
			if err := awgCheckJSONValue(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := awgCheckJSONValue(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("неверная структура JSON")
	}
	_, err = d.Token()
	return err
}

func awgDecodeRoutingDocument(raw json.RawMessage) (AWGRoutingDocument, error) {
	var doc AWGRoutingDocument
	if len(raw) > AWGRoutingRequestLimit {
		return doc, fmt.Errorf("документ слишком большой")
	}
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte{'"'}) {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return doc, err
		}
		raw = []byte(text)
	}
	if err := DecodeAWGRoutingJSON(raw, &doc, AWGRoutingDocumentLimit); err != nil {
		return doc, err
	}
	var shape map[string]json.RawMessage
	_ = json.Unmarshal(raw, &shape)
	if len(shape["routing"]) == 0 || bytes.Equal(bytes.TrimSpace(shape["routing"]), []byte("null")) || len(shape["connections"]) == 0 || bytes.Equal(bytes.TrimSpace(shape["connections"]), []byte("null")) {
		return doc, fmt.Errorf("routing и connections обязательны")
	}
	var routingShape map[string]json.RawMessage
	_ = json.Unmarshal(shape["routing"], &routingShape)
	if len(routingShape["zones"]) == 0 || bytes.Equal(bytes.TrimSpace(routingShape["zones"]), []byte("null")) {
		return doc, fmt.Errorf("routing.zones должен быть массивом")
	}
	if err := awgValidateRoutingDocument(doc); err != nil {
		return doc, err
	}
	return doc, nil
}

func awgPortableText(text string, limit int) bool {
	if len(text) > limit || !utf8.ValidString(text) {
		return false
	}
	for _, r := range text {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

func awgPortableRef(ref string) bool {
	if ref == "" || len(ref) > 128 {
		return false
	}
	for _, r := range ref {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_.:-", r) {
			continue
		}
		return false
	}
	return true
}

func awgValidateRoutingDocument(doc AWGRoutingDocument) error {
	if doc.Format != awgRoutingFormat || doc.Version != 1 {
		return fmt.Errorf("неподдерживаемый формат или версия файла правил")
	}
	if len(doc.Connections) > 256 || len(doc.Warnings) > 32 {
		return fmt.Errorf("слишком много подключений или предупреждений")
	}
	refs := map[string]AWG2ConnectionRef{}
	for _, ref := range doc.Connections {
		if !awgPortableRef(ref.Ref) || !awgPortableText(ref.Label, 512) {
			return fmt.Errorf("неверная ссылка подключения")
		}
		if _, exists := refs[ref.Ref]; exists {
			return fmt.Errorf("повторяющаяся ссылка подключения: %s", ref.Ref)
		}
		if ref.Endpoint != "" {
			if _, err := awgCanonicalEndpoint(ref.Endpoint); err != nil {
				return fmt.Errorf("подключение %s: %w", ref.Ref, err)
			}
		}
		if ref.ServerPublicKey != "" {
			if _, err := awgCanonicalPublicKey(ref.ServerPublicKey); err != nil {
				return fmt.Errorf("подключение %s: %w", ref.Ref, err)
			}
		}
		if ref.ClientIface != "" && !validAWGClientIfaceName(ref.ClientIface) || ref.Protocol != "" && !awgValidPortableProtocol(ref.Protocol) {
			return fmt.Errorf("неверные параметры подключения %s", ref.Ref)
		}
		if ref.Fingerprint != awgConnectionFingerprint(ref) {
			return fmt.Errorf("отпечаток подключения %s не совпадает с параметрами", ref.Ref)
		}
		refs[ref.Ref] = ref
	}
	for _, warning := range doc.Warnings {
		if !awgPortableText(warning, 1024) {
			return fmt.Errorf("неверное предупреждение")
		}
	}
	if err := awgValidatePortableRouting(doc.Routing, false); err != nil {
		return err
	}
	for _, z := range doc.Routing.Zones {
		for _, ref := range append([]string{z.TunnelID}, z.FallbackTunnelIDs...) {
			if ref == "" {
				return fmt.Errorf("правило %q не содержит ссылку подключения", z.Name)
			}
			if _, exists := refs[ref]; !exists {
				return fmt.Errorf("правило %q ссылается на неизвестное подключение %s", z.Name, ref)
			}
		}
	}
	return nil
}

func awgValidatePortableRouting(rc awg.RoutingConfig, allowDependencies bool) error {
	switch rc.Mode {
	case "", "off", "zones", "full", "include", "exclude":
	default:
		return fmt.Errorf("неверный режим маршрутизации")
	}
	if rc.DomainSource != "" && rc.DomainSource != "resolve" && rc.DomainSource != "dnsproxy" {
		return fmt.Errorf("неверный источник доменов")
	}
	if rc.MTU != 0 && (rc.MTU < 68 || rc.MTU > 9000) {
		return fmt.Errorf("неверный MTU")
	}
	if len(rc.Zones) > awgRoutingMaxRules {
		return fmt.Errorf("слишком много правил (максимум %d)", awgRoutingMaxRules)
	}
	entries := 0
	for _, z := range rc.Zones {
		if !awgPortableText(z.Name, 512) || z.Order < 0 || z.Order > awgRoutingMaxRules || z.TunnelID != "" && !awgPortableRef(z.TunnelID) {
			return fmt.Errorf("неверные параметры правила %q", z.Name)
		}
		if z.Route != "" && z.Route != "tunnel" && z.Route != "direct" || z.Mode != "" && z.Mode != "include" && z.Mode != "exclude" {
			return fmt.Errorf("неверное направление правила %q", z.Name)
		}
		if len(z.FallbackTunnelIDs) > 256 {
			return fmt.Errorf("слишком много резервных подключений")
		}
		seen := map[string]bool{}
		for _, id := range z.FallbackTunnelIDs {
			if !awgPortableRef(id) || seen[id] {
				return fmt.Errorf("неверная или повторяющаяся ссылка резервного подключения")
			}
			seen[id] = true
		}
		entries += len(z.Domains) + len(z.IPs) + len(z.SourceIPs)
		if entries > awgRoutingMaxEntries {
			return fmt.Errorf("слишком много записей в правилах")
		}
		for _, entry := range z.Domains {
			if err := awgValidatePortableDomain(entry, allowDependencies); err != nil {
				return fmt.Errorf("правило %q: %w", z.Name, err)
			}
		}
		for _, entry := range append(append([]string(nil), z.IPs...), z.SourceIPs...) {
			if !isIPish(entry) {
				return fmt.Errorf("правило %q: неверный IP/CIDR %q", z.Name, entry)
			}
		}
	}
	return nil
}

func awgValidatePortableDomain(raw string, dependencies bool) error {
	if !awgPortableText(raw, 4096) || strings.TrimSpace(raw) != raw || raw == "" {
		return fmt.Errorf("неверная запись домена")
	}
	lower := strings.ToLower(raw)
	for _, prefix := range []string{"list:", "geosite:", "geoip:"} {
		if strings.HasPrefix(lower, prefix) {
			if !dependencies || !awgPortableRef(raw[len(prefix):]) {
				return fmt.Errorf("локальная ссылка %q должна быть экспортирована как снимок", raw)
			}
			return nil
		}
	}
	if strings.HasPrefix(lower, "regexp:") {
		raw = "[re]" + raw[len("regexp:"):]
	}
	if strings.HasPrefix(raw, "[re]") {
		if len(raw) == 4 {
			return fmt.Errorf("пустое регулярное выражение")
		}
		if _, err := regexp.Compile(strings.ToLower(raw[4:])); err != nil {
			return fmt.Errorf("неверное регулярное выражение: %w", err)
		}
		return nil
	}
	if strings.HasPrefix(lower, "keyword:") {
		keyword := raw[len("keyword:"):]
		if keyword == "" || strings.ContainsAny(keyword, "/\\\"'`;$|&<> ") {
			return fmt.Errorf("неверная keyword запись")
		}
		return nil
	}
	for _, prefix := range []string{"domain:", "full:"} {
		if strings.HasPrefix(lower, prefix) {
			raw = raw[len(prefix):]
			break
		}
	}
	if isIPish(raw) {
		return nil
	}
	if strings.ContainsAny(raw, "*#") {
		if strings.ContainsAny(raw, "/\\\"'`;$|&<>: ") {
			return fmt.Errorf("неверная маска домена")
		}
		for _, r := range raw {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(".-_*#", r) {
				continue
			}
			return fmt.Errorf("неверная маска домена")
		}
		return nil
	}
	if !routingHostname(strings.ToLower(strings.TrimSuffix(raw, "."))) {
		return fmt.Errorf("неверный домен %q", raw)
	}
	return nil
}

func awgRoutingLiveReferences(servers []*managedServer) map[string]AWG2ConnectionRef {
	refs := make(map[string]AWG2ConnectionRef, len(servers))
	for _, server := range servers {
		ref := awgConnectionReference(server)
		if ref.Ref != "" {
			refs[ref.Ref] = ref
		}
	}
	return refs
}

func awgRoutingDocumentReferences(doc AWGRoutingDocument) []AWG2ConnectionRef {
	used := map[string]bool{}
	for _, z := range doc.Routing.Zones {
		used[z.TunnelID] = true
		for _, ref := range z.FallbackTunnelIDs {
			used[ref] = true
		}
	}
	refs := make([]AWG2ConnectionRef, 0, len(used))
	for _, ref := range doc.Connections {
		if used[ref.Ref] {
			refs = append(refs, ref)
		}
	}
	return refs
}

func awgRoutingPreview(doc AWGRoutingDocument, live map[string]AWG2ConnectionRef) AWGRoutingImportPlan {
	plan := AWGRoutingImportPlan{Connections: []AWGRoutingConnectionPlan{}, RuleCount: len(doc.Routing.Zones), Warnings: append([]string{}, doc.Warnings...)}
	candidates := make([]AWGRoutingCandidate, 0, len(live))
	for id, ref := range live {
		if ref.Fingerprint != "" {
			candidates = append(candidates, AWGRoutingCandidate{ID: id, Label: ref.Label, Endpoint: ref.Endpoint, ClientIface: ref.ClientIface, Protocol: ref.Protocol, Fingerprint: ref.Fingerprint})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Label == candidates[j].Label {
			return candidates[i].ID < candidates[j].ID
		}
		return candidates[i].Label < candidates[j].Label
	})
	for _, source := range awgRoutingDocumentReferences(doc) {
		item := AWGRoutingConnectionPlan{Source: source, State: "missing", Candidates: append([]AWGRoutingCandidate{}, candidates...)}
		for _, candidate := range candidates {
			if source.Fingerprint != "" && candidate.Fingerprint == source.Fingerprint {
				if item.State == "matched" || item.State == "ambiguous" {
					item.State = "ambiguous"
					item.MatchedTunnelID = ""
				} else {
					item.State = "matched"
					item.MatchedTunnelID = candidate.ID
				}
			}
		}
		if current, exists := live[source.Ref]; exists && item.State != "matched" && (source.Fingerprint == "" || source.Fingerprint != current.Fingerprint) {
			item.Reason = "identity_changed"
		}
		plan.Connections = append(plan.Connections, item)
	}
	for _, z := range doc.Routing.Zones {
		if z.WaitingForConnection {
			plan.WaitingRuleCount++
		}
	}
	return plan
}

func (svc *Service) AWG2PreviewRoutingRules(raw json.RawMessage) (AWGRoutingImportPlan, error) {
	doc, err := awgDecodeRoutingDocument(raw)
	if err != nil {
		return AWGRoutingImportPlan{}, err
	}
	_, unlock := svc.lockClientOps(false)
	defer unlock()
	plan := awgRoutingPreview(doc, awgRoutingLiveReferences(svc.serverSnapshot()))
	plan.PolicyHash = awgRoutingPolicyHash(svc.globalRoutingConfig(svc.awgRoutingRules()), svc.connectionRefSnapshot())
	return plan, nil
}

// Preparation is pure; no manager, persisted state or kernel changes precede
// complete validation, including a fresh target identity comparison.
func awgPrepareRoutingImport(doc AWGRoutingDocument, request AWGRoutingImportRequest, live, retained map[string]AWG2ConnectionRef, base awg.RoutingConfig) (awg.RoutingConfig, map[string]AWG2ConnectionRef, error) {
	if request.Mode != "replace" && request.Mode != "append" {
		return awg.RoutingConfig{}, nil, fmt.Errorf("выберите replace или append")
	}
	if request.Mode == "replace" && request.BaseRouting != nil {
		return awg.RoutingConfig{}, nil, fmt.Errorf("base_routing используется только при добавлении")
	}
	if request.BaseRouting != nil {
		base = *request.BaseRouting
		if err := awgValidatePortableRouting(base, true); err != nil {
			return awg.RoutingConfig{}, nil, err
		}
	}
	plan := awgRoutingPreview(doc, live)
	known := map[string]bool{}
	remapped := map[string]string{}
	extra := map[string]AWG2ConnectionRef{}
	for _, item := range plan.Connections {
		source := item.Source
		known[source.Ref] = true
		target, explicit := request.Mappings[source.Ref]
		if !explicit {
			if item.State != "matched" {
				return awg.RoutingConfig{}, nil, fmt.Errorf("выберите подключение или ожидание для %q", source.Label)
			}
			target = item.MatchedTunnelID
		}
		if target == "" {
			detached := awgDetachedRoutingReference(source, live, retained, extra)
			remapped[source.Ref] = detached.Ref
			extra[detached.Ref] = detached
			continue
		}
		current, exists := live[target]
		if !exists || current.Fingerprint == "" {
			return awg.RoutingConfig{}, nil, fmt.Errorf("выбранное подключение %s отсутствует или не настроено", target)
		}
		fingerprint, supplied := request.MappingFingerprints[source.Ref]
		if supplied && fingerprint != current.Fingerprint || !supplied && current.Fingerprint != source.Fingerprint {
			return awg.RoutingConfig{}, nil, fmt.Errorf("подключение %s изменилось; обновите предварительный просмотр и повторите выбор", target)
		}
		remapped[source.Ref] = target
	}
	for ref := range request.Mappings {
		if !known[ref] {
			return awg.RoutingConfig{}, nil, fmt.Errorf("неизвестная ссылка в выборе: %s", ref)
		}
	}
	for ref := range request.MappingFingerprints {
		if !known[ref] || request.Mappings[ref] == "" {
			return awg.RoutingConfig{}, nil, fmt.Errorf("лишний отпечаток выбора: %s", ref)
		}
	}
	rc := doc.Routing
	rc.Zones = cloneAWGZones(doc.Routing.Zones)
	for i := range rc.Zones {
		z := &rc.Zones[i]
		z.TunnelID = remapped[z.TunnelID]
		_, waiting := extra[z.TunnelID]
		z.WaitingForConnection = waiting
		for j, fallback := range z.FallbackTunnelIDs {
			z.FallbackTunnelIDs[j] = remapped[fallback]
		}
		// Two public references may be explicitly mapped to the same target.
		if len(z.FallbackTunnelIDs) > 0 {
			z.FallbackTunnelIDs, _ = normalizeFallbackTunnelIDs(z.TunnelID, z.FallbackTunnelIDs, nil)
		}
	}
	if request.Mode == "append" {
		imported := rc.Zones
		rc = base
		rc.Zones = append(cloneAWGZones(base.Zones), imported...)
	}
	if err := awgValidatePortableRouting(rc, true); err != nil {
		return awg.RoutingConfig{}, nil, err
	}
	for i := range rc.Zones {
		rc.Zones[i].Order = i + 1
	}
	if rc.Mode == "" || rc.Mode == "include" || rc.Mode == "exclude" {
		rc.Mode = "zones"
	}
	return rc, extra, nil
}

func awgDetachedRoutingReference(source AWG2ConnectionRef, live, retained, extra map[string]AWG2ConnectionRef) AWG2ConnectionRef {
	identity := source.Ref + "\x00" + source.Fingerprint + "\x00" + source.Endpoint + "\x00" + source.ServerPublicKey + "\x00" + source.Protocol + "\x00" + source.ClientIface
	h := sha256.Sum256([]byte(identity))
	base := "pending-import-" + hex.EncodeToString(h[:16])
	for suffix := 0; ; suffix++ {
		id := base
		if suffix > 0 {
			id = fmt.Sprintf("%s-%d", base, suffix)
		}
		if _, exists := live[id]; exists {
			continue
		}
		candidate := source
		candidate.Ref = id
		if previous, exists := retained[id]; exists && !awgSameDetachedIdentity(previous, candidate) {
			continue
		}
		if previous, exists := extra[id]; exists && !awgSameDetachedIdentity(previous, candidate) {
			continue
		}
		return candidate
	}
}

func awgSameDetachedIdentity(a, b AWG2ConnectionRef) bool {
	return a.Fingerprint == b.Fingerprint && a.Endpoint == b.Endpoint && a.ServerPublicKey == b.ServerPublicKey && a.Protocol == b.Protocol && a.ClientIface == b.ClientIface
}

func (svc *Service) AWG2ImportRoutingRules(request AWGRoutingImportRequest) (AWGRoutingImportResult, error) {
	return svc.awgImportRoutingRulesWithApply(request, svc.awgApplyMultiHostRoutesOSErr)
}

// Separate the runtime installer so persistence/retry tests cannot alter a
// host's real firewall, interfaces or routes, including native router tests.
func (svc *Service) awgImportRoutingRulesWithApply(request AWGRoutingImportRequest, apply func() error) (AWGRoutingImportResult, error) {
	doc, err := awgDecodeRoutingDocument(request.Document)
	if err != nil {
		return AWGRoutingImportResult{}, err
	}
	_, unlock := svc.lockClientOps(false)
	defer unlock()
	base := svc.globalRoutingConfig(svc.awgRoutingRules())
	rc, refs, err := awgPrepareRoutingImport(doc, request, awgRoutingLiveReferences(svc.serverSnapshot()), svc.connectionRefSnapshot(), base)
	if err != nil {
		return AWGRoutingImportResult{}, err
	}
	if rc.MTU == 0 {
		rc.MTU = base.MTU
	}
	currentRefs := svc.connectionRefSnapshot()
	candidateRefs := cloneAWGConnectionRefs(currentRefs)
	if candidateRefs == nil {
		candidateRefs = map[string]AWG2ConnectionRef{}
	}
	for id, ref := range refs {
		candidateRefs[id] = ref
	}
	already, err := awgRoutingImportAllowed(request.ExpectedPolicyHash, awgRoutingPolicyHash(base, currentRefs), awgRoutingPolicyHash(rc, candidateRefs))
	if err != nil {
		return AWGRoutingImportResult{}, err
	}
	if already {
		result := svc.awgRoutingImportResult()
		if !svc.RoutingDNSReadiness().Ready {
			return result, apply()
		}
		return result, nil
	}
	if err := svc.awgSaveRoutingRulesWithRefs(rc, refs); err != nil {
		return AWGRoutingImportResult{}, err
	}
	result := svc.awgRoutingImportResult()
	if err := apply(); err != nil {
		return result, err
	}
	return result, nil
}

func (svc *Service) awgRoutingImportResult() AWGRoutingImportResult {
	result := AWGRoutingImportResult{Routing: svc.globalRoutingConfig(svc.awgRoutingRules()), RoutingRevision: svc.zonesRevision.Load()}
	result.RuleCount = len(result.Routing.Zones)
	for _, z := range result.Routing.Zones {
		if z.WaitingForConnection {
			result.WaitingRuleCount++
		}
	}
	return result
}

var ErrAWGRoutingPolicyConflict = errors.New("маршрутизация изменилась; обновите проверку перед импортом")

func awgRoutingImportAllowed(expected, current, candidate string) (bool, error) {
	decoded, err := hex.DecodeString(expected)
	if err != nil || len(decoded) != sha256.Size {
		return false, fmt.Errorf("нужен expected_policy_hash из предварительного просмотра")
	}
	if current == expected {
		return false, nil
	}
	if current == candidate {
		return true, nil
	} // ACK lost: never append the file twice.
	return false, ErrAWGRoutingPolicyConflict
}

// Compare semantic persisted policy, excluding the derived Active status and
// labels. Preserve rule order, explicit subdomain tri-state and public identity.
func awgRoutingPolicyHash(rc awg.RoutingConfig, refs map[string]AWG2ConnectionRef) string {
	rc = routingSettingsFrom(rc).apply(awg.RoutingConfig{Zones: cloneAWGZones(rc.Zones)})
	if rc.Mode == "include" || rc.Mode == "exclude" {
		rc.Mode = "zones"
	}
	identities := map[string]AWG2ConnectionRef{}
	for i := range rc.Zones {
		z := &rc.Zones[i]
		z.Order = i + 1
		z.Route = z.RouteValue()
		if z.Mode == "" {
			if z.Route == "direct" {
				z.Mode = "exclude"
			} else {
				z.Mode = "include"
			}
		}
		if z.Domains == nil {
			z.Domains = []string{}
		}
		if z.IPs == nil {
			z.IPs = []string{}
		}
		if z.SourceIPs == nil {
			z.SourceIPs = []string{}
		}
		if z.Route == "direct" && !z.WaitingForConnection {
			z.FallbackTunnelIDs = nil
		} else {
			z.FallbackTunnelIDs, _ = normalizeFallbackTunnelIDs(z.TunnelID, z.FallbackTunnelIDs, nil)
		}
		for _, id := range append([]string{z.TunnelID}, z.FallbackTunnelIDs...) {
			ref := refs[id]
			ref.Ref = id
			ref.Label = ""
			identities[id] = ref
		}
	}
	encoded, _ := json.Marshal(struct {
		Routing     awg.RoutingConfig            `json:"routing"`
		Connections map[string]AWG2ConnectionRef `json:"connections"`
	}{rc, identities})
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:])
}
