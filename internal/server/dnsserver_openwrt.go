package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func (s *Server) dnsServerOpenWrt(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	state, err := s.app.DNSServer().OpenWrtDNSStatus(ctx)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) dnsServerOpenWrtApply(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Interface string `json:"interface"`
		Instance  string `json:"instance"`
		Revision  string `json:"revision"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(in.Revision) == "" {
		httpErr(w, http.StatusBadRequest, fmt.Errorf("обновите состояние DNS OpenWrt перед применением"))
		return
	}
	s.portsMu.Lock()
	defer s.portsMu.Unlock()
	if err := s.app.DNSServer().ApplyOpenWrtDNS(r.Context(), in.Interface, in.Instance, in.Revision); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	s.dnsServerOpenWrt(w, r)
}

func (s *Server) dnsServerOpenWrtRestore(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Revision string `json:"revision"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(in.Revision) == "" {
		httpErr(w, http.StatusBadRequest, fmt.Errorf("обновите состояние DNS OpenWrt перед восстановлением"))
		return
	}
	s.portsMu.Lock()
	defer s.portsMu.Unlock()
	if err := s.app.DNSServer().RestoreOpenWrtDNS(r.Context(), in.Revision); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	s.dnsServerOpenWrt(w, r)
}
