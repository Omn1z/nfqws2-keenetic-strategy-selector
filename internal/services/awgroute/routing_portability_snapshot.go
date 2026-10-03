package awgroute

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"nfqws2strategy/internal/services/awg"
	"nfqws2strategy/internal/tools/geo"
)

// Snapshot dependencies in a copy, keeping the original policy and files intact.
// Import therefore needs no local list names, geo files or network downloads.
func awgSnapshotRoutingDependencies(rc awg.RoutingConfig, lookup func(string, string) ([]string, error)) (awg.RoutingConfig, []string, error) {
	rc.Zones = cloneAWGZones(rc.Zones)
	count := 0
	used := false
	for i := range rc.Zones {
		z := &rc.Zones[i]
		domains := make([]string, 0, len(z.Domains))
		for _, original := range z.Domains {
			lower := strings.ToLower(original)
			kind, name := "", ""
			for _, prefix := range []string{"list:", "geosite:", "geoip:"} {
				if strings.HasPrefix(lower, prefix) {
					kind, name = prefix[:len(prefix)-1], original[len(prefix):]
					break
				}
			}
			if kind == "" {
				domains = append(domains, original)
				continue
			}
			entries, err := lookup(kind, name)
			if err != nil || len(entries) == 0 {
				return awg.RoutingConfig{}, nil, fmt.Errorf("правило %q: источник %s отсутствует, пуст или повреждён: %v", z.Name, original, err)
			}
			used = true
			for _, entry := range entries {
				entry = strings.TrimSpace(entry)
				// Nested list/geo references are not recursively expanded by the
				// routing engine. Reject them instead of changing that meaning.
				if err := awgValidatePortableDomain(entry, false); err != nil {
					return awg.RoutingConfig{}, nil, fmt.Errorf("источник %s: %w", original, err)
				}
				if isIPish(entry) {
					z.IPs = append(z.IPs, entry)
				} else {
					// Dependency entries already have the matcher's native syntax;
					// exporting an xray prefix would run expansion a second time.
					lowerEntry := strings.ToLower(entry)
					for _, prefix := range []string{"full:", "domain:", "regexp:", "keyword:"} {
						if strings.HasPrefix(lowerEntry, prefix) {
							return awg.RoutingConfig{}, nil, fmt.Errorf("источник %s содержит вложенный префикс %s; используйте обычное имя или [re]", original, prefix)
						}
					}
					domains = append(domains, entry)
				}
				count++
				if count > awgRoutingMaxEntries {
					return awg.RoutingConfig{}, nil, fmt.Errorf("снимок списков превышает %d записей", awgRoutingMaxEntries)
				}
			}
		}
		z.Domains = domains
	}
	if err := awgValidatePortableRouting(rc, false); err != nil {
		return awg.RoutingConfig{}, nil, err
	}
	warnings := []string{}
	if used {
		warnings = append(warnings, "Ссылки list:/geosite:/geoip: заменены снимком содержимого. На другом роутере эти записи не обновляются вместе с исходным списком.")
	}
	return rc, warnings, nil
}

func (svc *Service) awgRoutingDependency(kind, name string) ([]string, error) {
	if kind == "list" {
		return awgReadPortableList(awgNfqwsListsDir, name)
	}
	geoKind := geo.KindGeoSite
	if kind == "geoip" {
		geoKind = geo.KindGeoIP
	}
	return awgReadPortableGeo(svc.store.Path("geo"), geoKind, name)
}

func awgReadPortableGeo(directory, kind, category string) ([]string, error) {
	data, err := awgReadPortableFile(filepath.Join(filepath.Dir(directory), "geo_meta.json"), 64<<10)
	if err != nil {
		return nil, err
	}
	meta := map[string]string{}
	if err := DecodeAWGRoutingJSON(data, &meta, 64<<10); err != nil {
		return nil, err
	}
	files := []string{}
	for name, entryKind := range meta {
		if entryKind == kind {
			if name == "." || name == ".." || name != filepath.Base(name) || strings.ContainsAny(name, "/\\:") {
				return nil, fmt.Errorf("неверное имя geo-файла")
			}
			files = append(files, name)
		}
	}
	sort.Strings(files)
	out := []string{}
	seen := map[string]bool{}
	for _, file := range files {
		// Export is occasional; parse each bounded file once rather than
		// accepting LookupCategory's intentionally soft missing-file behavior.
		data, err := awgReadPortableFile(filepath.Join(directory, file), 64<<20)
		if err != nil {
			return nil, err
		}
		categories := geo.Parse(kind, data)
		if len(categories) == 0 {
			return nil, fmt.Errorf("geo-файл %s пуст или повреждён", file)
		}
		for _, entry := range categories[strings.ToLower(category)] {
			if !seen[entry] {
				seen[entry] = true
				out = append(out, entry)
			}
			if len(out) > awgRoutingMaxEntries {
				return nil, fmt.Errorf("слишком много geo-записей")
			}
		}
	}
	return out, nil
}

func awgReadPortableFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("файл превышает ограничение размера")
	}
	return data, nil
}

func awgReadPortableList(directory, name string) ([]string, error) {
	if !awgPortableRef(name) || name == "." || name == ".." || strings.ContainsAny(name, "/\\:") {
		return nil, fmt.Errorf("неверное имя списка")
	}
	if !strings.HasSuffix(name, ".list") && !strings.HasSuffix(name, ".gz") {
		name += ".list"
	}
	var data []byte
	var lastErr error
	for _, file := range []string{name, name + ".gz"} {
		f, err := os.Open(filepath.Join(directory, file))
		if err != nil {
			lastErr = err
			continue
		}
		var reader io.Reader = f
		var gz *gzip.Reader
		if strings.HasSuffix(file, ".gz") {
			gz, err = gzip.NewReader(f)
			if err != nil {
				f.Close()
				return nil, err
			}
			reader = gz
		}
		data, err = io.ReadAll(io.LimitReader(reader, AWGRoutingDocumentLimit+1))
		if gz != nil {
			gz.Close()
		}
		f.Close()
		if err != nil {
			return nil, err
		}
		if len(data) > AWGRoutingDocumentLimit {
			return nil, fmt.Errorf("содержимое списка больше %d байт", AWGRoutingDocumentLimit)
		}
		break
	}
	if data == nil {
		return nil, lastErr
	}
	out := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, ";") {
			out = append(out, line)
		}
	}
	return out, nil
}

func (svc *Service) AWG2ExportRoutingRules(draft *awg.RoutingConfig) (AWGRoutingDocument, error) {
	_, unlock := svc.lockClientOps(false)
	defer unlock()
	rc := svc.globalRoutingConfig(svc.awgRoutingRules())
	if draft != nil {
		rc = *draft
	}
	if err := awgValidatePortableRouting(rc, true); err != nil {
		return AWGRoutingDocument{}, err
	}
	rc, warnings, err := awgSnapshotRoutingDependencies(rc, svc.awgRoutingDependency)
	if err != nil {
		return AWGRoutingDocument{}, err
	}
	if rc.Zones == nil {
		rc.Zones = []awg.Zone{}
	}
	refs := svc.connectionRefSnapshot()
	defaultID := svc.activeServerID()
	if _, exists := refs[defaultID]; !exists {
		defaultID = ""
	}
	connections := []AWG2ConnectionRef{}
	seen := map[string]bool{}
	for i := range rc.Zones {
		z := &rc.Zones[i]
		if z.TunnelID == "" {
			if !z.WaitingForConnection {
				z.TunnelID = defaultID
			}
			if z.TunnelID == "" {
				z.TunnelID = fmt.Sprintf("pending-unassigned-%d", i+1)
			}
		}
		for _, id := range append([]string{z.TunnelID}, z.FallbackTunnelIDs...) {
			if seen[id] {
				continue
			}
			seen[id] = true
			ref, exists := refs[id]
			if !exists {
				ref = AWG2ConnectionRef{Ref: id, Label: id}
			}
			connections = append(connections, ref)
		}
	}
	doc := AWGRoutingDocument{Format: awgRoutingFormat, Version: 1, Routing: rc, Connections: connections, Warnings: warnings}
	if err := awgValidateRoutingDocument(doc); err != nil {
		return AWGRoutingDocument{}, err
	}
	// Match the readable file emitted by the UI, so every successful export
	// fits the same file-size limit when imported again.
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil || len(encoded) > AWGRoutingDocumentLimit {
		return AWGRoutingDocument{}, fmt.Errorf("файл правил превышает %d байт", AWGRoutingDocumentLimit)
	}
	return doc, nil
}
