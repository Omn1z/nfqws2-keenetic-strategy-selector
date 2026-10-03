package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"nfqws2strategy/internal/services/awgroute"
	"nfqws2strategy/internal/services/dnsserver"
)

const dnsImportDocumentLimit = 16 << 20
const dnsImportRequestLimit = 64 << 20

var errDNSImportSize = errors.New("файл настроек DNS превышает 16 МиБ")

type dnsImportRequest struct {
	Document           json.RawMessage `json:"document"`
	Mapping            *string         `json:"mapping,omitempty"`
	MappingFingerprint string          `json:"mapping_fingerprint,omitempty"`
	BaseHash           string          `json:"base_hash,omitempty"`
}
type dnsImportVPNPlan struct {
	SourceID   string                       `json:"source_id"`
	State      string                       `json:"state"`
	MatchedID  string                       `json:"matched_id,omitempty"`
	Candidates []awgroute.AWG2ConnectionRef `json:"candidates"`
}
type dnsImportListener struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Address string `json:"address"`
	Enabled bool   `json:"enabled"`
}
type dnsImportPlan struct {
	Config   dnsserver.Config  `json:"config"`
	BaseHash string            `json:"base_hash"`
	Listener dnsImportListener `json:"listener"`
	VPN      dnsImportVPNPlan  `json:"vpn"`
	Warnings []string          `json:"warnings"`
}

// Verify exact JSON names and required values before Go's case-insensitive
// decoder can silently accept a misspelled field or turn null into false/zero.
// Null arrays from older exporters are harmless empty collections. The only
// legacy omissions are optional filtering and the new scheduler switch.
func dnsImportShape(raw json.RawMessage, typ reflect.Type, path string) error {
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if typ.Kind() == reflect.Slice {
			return nil
		}
		return fmt.Errorf("%s не может быть null", path)
	}
	switch typ.Kind() {
	case reflect.Struct:
		if typ.PkgPath() == "time" {
			return nil
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
			return fmt.Errorf("%s должен быть объектом", path)
		}
		allowed := map[string]reflect.StructField{}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name != "" && name != "-" {
				allowed[name] = f
			}
		}
		for name := range fields {
			if _, ok := allowed[name]; !ok {
				return fmt.Errorf("неизвестное поле %s.%s", path, name)
			}
		}
		for name, f := range allowed {
			value, ok := fields[name]
			optional := strings.Contains(f.Tag.Get("json"), "omitempty") || typ == reflect.TypeFor[dnsserver.Config]() && name == "scheduler_enabled"
			if !ok {
				if optional {
					continue
				}
				return fmt.Errorf("обязательное поле %s.%s отсутствует", path, name)
			}
			if err := dnsImportShape(value, f.Type, path+"."+name); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if typ == reflect.TypeFor[json.RawMessage]() {
			return nil
		}
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return fmt.Errorf("%s должен быть массивом", path)
		}
		for i, value := range values {
			if err := dnsImportShape(value, typ.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func decodeDNSImportDocument(raw json.RawMessage) (dnsServerSettingsExport, error) {
	doc := dnsServerSettingsExport{Config: dnsserver.Default()}
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte{'"'}) {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return doc, err
		}
		raw = []byte(text)
	}
	if len(raw) > dnsImportDocumentLimit {
		return doc, errDNSImportSize
	}
	raw = bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf})
	if err := awgroute.DecodeAWGRoutingJSON(raw, &doc, dnsImportDocumentLimit); err != nil {
		return doc, err
	}
	if err := dnsImportShape(raw, reflect.TypeFor[dnsServerSettingsExport](), "document"); err != nil {
		return doc, err
	}
	if doc.Format != dnsServerExportFormat || doc.Version != 1 || doc.ExportedAt.IsZero() {
		return doc, fmt.Errorf("неподдерживаемый формат/версия или отсутствует время экспорта DNS")
	}
	if len(doc.Connections) > 2049 {
		return doc, fmt.Errorf("слишком много ссылок VPN")
	}
	seen := map[string]bool{}
	for _, ref := range doc.Connections {
		if seen[ref.Ref] {
			return doc, fmt.Errorf("повторная ссылка VPN %s", ref.Ref)
		}
		if err := awgroute.ValidateAWGConnectionReference(ref); err != nil {
			return doc, err
		}
		seen[ref.Ref] = true
	}
	if err := doc.Config.NormalizeValidate(); err != nil {
		return doc, err
	}
	return doc, nil
}
func readDNSImport(w http.ResponseWriter, r *http.Request) (dnsImportRequest, dnsServerSettingsExport, error) {
	var in dnsImportRequest
	reader := http.MaxBytesReader(w, r.Body, dnsImportRequestLimit)
	defer reader.Close()
	raw, err := io.ReadAll(reader)
	if err != nil {
		return in, dnsServerSettingsExport{}, err
	}
	if err = awgroute.DecodeAWGRoutingJSON(raw, &in, dnsImportRequestLimit); err != nil {
		return in, dnsServerSettingsExport{}, err
	}
	if err = dnsImportShape(raw, reflect.TypeFor[dnsImportRequest](), "request"); err != nil {
		return in, dnsServerSettingsExport{}, err
	}
	doc, err := decodeDNSImportDocument(in.Document)
	return in, doc, err
}
func dnsConnectionIDs(cfg dnsserver.Config) []string {
	ids := map[string]bool{}
	if cfg.AWGFallback != "" && cfg.AWGFallback != "auto" && cfg.AWGFallback != "off" {
		ids[strings.TrimPrefix(cfg.AWGFallback, "awg:")] = true
	}
	for _, method := range cfg.DisabledMethods {
		if strings.HasPrefix(method.Route, "awg:") {
			ids[strings.TrimPrefix(method.Route, "awg:")] = true
		}
	}
	result := make([]string, 0, len(ids))
	for id := range ids {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}
func dnsExportConnections(cfg dnsserver.Config, live []awgroute.AWG2ConnectionRef) []awgroute.AWG2ConnectionRef {
	byID := map[string]awgroute.AWG2ConnectionRef{}
	for _, ref := range live {
		byID[ref.Ref] = ref
	}
	refs := []awgroute.AWG2ConnectionRef{}
	for _, id := range dnsConnectionIDs(cfg) {
		ref, ok := byID[id]
		if !ok {
			ref = awgroute.AWG2ConnectionRef{Ref: id, Label: id}
		}
		refs = append(refs, ref)
	}
	return refs
}
func prepareDNSImport(doc dnsServerSettingsExport, in dnsImportRequest, live []awgroute.AWG2ConnectionRef) (dnsImportPlan, error) {
	plan := dnsImportPlan{Config: doc.Config, Warnings: []string{}, VPN: dnsImportVPNPlan{SourceID: doc.Config.AWGFallback, Candidates: []awgroute.AWG2ConnectionRef{}}}
	bySource := map[string]awgroute.AWG2ConnectionRef{}
	for _, ref := range doc.Connections {
		bySource[ref.Ref] = ref
	}
	for _, ref := range live {
		if ref.Fingerprint != "" {
			plan.VPN.Candidates = append(plan.VPN.Candidates, ref)
		}
	}
	match := func(id string) string {
		source := bySource[id]
		if source.Fingerprint == "" {
			return ""
		}
		found := ""
		for _, target := range plan.VPN.Candidates {
			if target.Fingerprint == source.Fingerprint {
				if found != "" {
					return ""
				}
				found = target.Ref
			}
		}
		return found
	}
	sourceID := doc.Config.AWGFallback
	targetID := ""
	switch sourceID {
	case "auto", "off":
		plan.VPN.State = sourceID
	default:
		targetID = match(sourceID)
		if targetID != "" {
			plan.VPN.State = "matched"
			plan.VPN.MatchedID = targetID
			plan.Config.AWGFallback = targetID
		} else {
			plan.VPN.State = "missing"
			if bySource[sourceID].Fingerprint == "" {
				plan.VPN.State = "selection_required"
			} else {
				n := 0
				for _, target := range plan.VPN.Candidates {
					if target.Fingerprint == bySource[sourceID].Fingerprint {
						n++
					}
				}
				if n > 1 {
					plan.VPN.State = "ambiguous"
				}
			}
		}
	}
	if in.Mapping != nil {
		selected := *in.Mapping
		if selected == "auto" || selected == "off" {
			plan.Config.AWGFallback = selected
			plan.VPN.State = selected
			plan.VPN.MatchedID = ""
			targetID = ""
		} else {
			var selectedRef *awgroute.AWG2ConnectionRef
			for i := range plan.VPN.Candidates {
				if plan.VPN.Candidates[i].Ref == selected {
					selectedRef = &plan.VPN.Candidates[i]
					break
				}
			}
			if selectedRef == nil || in.MappingFingerprint == "" || in.MappingFingerprint != selectedRef.Fingerprint {
				return plan, fmt.Errorf("выбранный VPN отсутствует или изменился; повторите предварительную проверку")
			}
			targetID = selected
			plan.Config.AWGFallback = selected
			plan.VPN.MatchedID = selected
			plan.VPN.State = "matched"
		}
	}
	if plan.VPN.State != "auto" && plan.VPN.State != "off" && plan.VPN.State != "matched" {
		plan.Warnings = append(plan.Warnings, "Выберите VPN: локальный ID из файла не подтверждает идентичность подключения на этом роутере.")
	}
	methods := make([]dnsserver.DisabledMethod, 0, len(doc.Config.DisabledMethods))
	dropped := 0
	droppedIDs := map[string]bool{}
	for _, method := range doc.Config.DisabledMethods {
		if !strings.HasPrefix(method.Route, "awg:") {
			methods = append(methods, method)
			continue
		}
		id := strings.TrimPrefix(method.Route, "awg:")
		mapped := match(id)
		if id == sourceID && in.Mapping != nil {
			mapped = targetID
		}
		if mapped == "" {
			dropped++
			droppedIDs[id] = true
			continue
		}
		method.Route = "awg:" + mapped
		methods = append(methods, method)
	}
	plan.Config.DisabledMethods = methods
	if dropped > 0 {
		ids := make([]string, 0, len(droppedIDs))
		for id := range droppedIDs {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		if len(ids) > 10 {
			ids = append(ids[:10], "…")
		}
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("Не перенесены выключатели методов (%d) для неподтверждённых VPN: %s. Проверьте их после импорта.", dropped, strings.Join(ids, ", ")))
	}
	if err := plan.Config.NormalizeValidate(); err != nil {
		return plan, err
	}
	return plan, nil
}
func dnsImportError(w http.ResponseWriter, err error) {
	code := http.StatusBadRequest
	var large *http.MaxBytesError
	if errors.As(err, &large) || errors.Is(err, errDNSImportSize) {
		code = http.StatusRequestEntityTooLarge
	}
	if errors.Is(err, dnsserver.ErrImportConfigConflict) {
		code = http.StatusConflict
	}
	httpErr(w, code, err)
}
func (s *Server) previewDNSImport(doc dnsServerSettingsExport, in dnsImportRequest) (dnsImportPlan, error) {
	return s.previewDNSImportWithConnections(doc, in, s.app.DNSServerPublicConnections())
}

func (s *Server) previewDNSImportWithConnections(doc dnsServerSettingsExport, in dnsImportRequest, refs []awgroute.AWG2ConnectionRef) (dnsImportPlan, error) {
	plan, err := prepareDNSImport(doc, in, refs)
	if err != nil {
		return plan, err
	}
	if err := validateSystemPorts(systemPorts{PanelPort: s.app.PanelPort(), DNSPort: plan.Config.DNSPort}); err != nil {
		return plan, err
	}
	cfg, host, err := s.app.DNSServer().ValidateImportedConfig(plan.Config)
	if err != nil {
		return plan, err
	}
	plan.Config = cfg
	plan.BaseHash = dnsserver.ConfigDigest(s.app.DNSServer().Config())
	plan.Listener = dnsImportListener{Host: host, Port: cfg.DNSPort, Address: net.JoinHostPort(host, strconv.Itoa(cfg.DNSPort)), Enabled: cfg.Enabled}
	return plan, nil
}
func (s *Server) dnsServerImportPreview(w http.ResponseWriter, r *http.Request) {
	in, doc, err := readDNSImport(w, r)
	if err != nil {
		dnsImportError(w, err)
		return
	}
	s.portsMu.Lock()
	defer s.portsMu.Unlock()
	plan, err := s.previewDNSImport(doc, in)
	if err != nil {
		dnsImportError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, plan)
}
func (s *Server) dnsServerImport(w http.ResponseWriter, r *http.Request) {
	in, doc, err := readDNSImport(w, r)
	if err != nil {
		dnsImportError(w, err)
		return
	}
	s.portsMu.Lock()
	defer s.portsMu.Unlock()
	// Keep identity validation and DNS persistence/startup in the same AWG
	// operation: an endpoint edit/delete cannot swap a validated target mid-apply.
	err = s.app.WithDNSServerPublicConnections(func(refs []awgroute.AWG2ConnectionRef) error {
		plan, err := s.previewDNSImportWithConnections(doc, in, refs)
		if err != nil {
			return err
		}
		if plan.VPN.State != "auto" && plan.VPN.State != "off" && plan.VPN.State != "matched" {
			return fmt.Errorf("выберите подключение VPN до импорта")
		}
		return s.app.DNSServer().ImportConfig(plan.Config, in.BaseHash)
	})
	if err != nil {
		dnsImportError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.app.DNSServer().Status())
}
