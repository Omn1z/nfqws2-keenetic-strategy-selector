package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"nfqws2strategy/internal/services/awgroute"
	"nfqws2strategy/internal/services/dnsserver"
)

const dnsServerExportFormat = "nfqws2-strategy-dnsserver"

// Export the complete saved configuration rather than a status or the partial
// settings form. Runtime answers, logs and VPN credentials never enter this DTO.
type dnsServerSettingsExport struct {
	Format      string                       `json:"format"`
	Version     int                          `json:"version"`
	ExportedAt  time.Time                    `json:"exported_at"`
	Config      dnsserver.Config             `json:"config"`
	Connections []awgroute.AWG2ConnectionRef `json:"connections,omitempty"`
}

func (s *Server) dnsServerExport(w http.ResponseWriter, r *http.Request) {
	cfg := s.app.DNSServer().Config()
	writeDNSServerSettingsExport(w, cfg, time.Now(), dnsExportConnections(cfg, s.app.DNSServerPublicConnections()))
}

func writeDNSServerSettingsExport(w http.ResponseWriter, cfg dnsserver.Config, now time.Time, refs ...[]awgroute.AWG2ConnectionRef) {
	now = now.UTC()
	doc := dnsServerSettingsExport{Format: dnsServerExportFormat, Version: 1, ExportedAt: now, Config: cfg}
	if len(refs) != 0 {
		doc.Connections = refs[0]
	}
	// The browser downloads indented JSON. Refuse a file that our import cannot
	// read, even if the compact API response would fit its document limit.
	pretty, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		dnsImportError(w, err)
		return
	}
	if len(pretty) > dnsImportDocumentLimit {
		dnsImportError(w, errDNSImportSize)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="dns-server-settings-%s.json"`, now.Format("20060102-150405")))
	writeJSON(w, http.StatusOK, doc)
}
