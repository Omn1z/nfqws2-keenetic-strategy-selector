package server

import (
	"fmt"
	"net/http"
)

func (s *Server) dnsServerShadowRenew(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Confirm bool `json:"confirm"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	if !in.Confirm {
		httpErr(w, http.StatusBadRequest, fmt.Errorf("подтвердите обновление DHCP WAN: возможно краткое прерывание интернета"))
		return
	}
	result, err := s.app.DNSServer().RenewShadowDNS(r.Context(), in.Confirm)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "result": result})
}

func (s *Server) dnsServerShadowDiagnostics(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	if in.Enabled == nil {
		httpErr(w, http.StatusBadRequest, fmt.Errorf("укажите enabled: true или false"))
		return
	}
	if err := s.app.DNSServer().SetShadowDiagnostics(*in.Enabled); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.dnsServerStatus(w, r)
}
