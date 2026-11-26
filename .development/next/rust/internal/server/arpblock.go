package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"nfqws2strategy/internal/services/arpblock"
)

func (s *Server) getARPBlock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	v, err := s.app.ARPBlockView(r.Context())
	if err != nil {
		httpErr(w, http.StatusServiceUnavailable, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) setARPBlockIsolation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var in struct {
		Segment  string `json:"segment"`
		Enabled  *bool  `json:"enabled"`
		Revision string `json:"revision"`
	}
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&in); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	if in.Enabled == nil || in.Segment == "" || len(in.Revision) != 64 || decoder.Decode(new(any)) != io.EOF {
		httpErr(w, http.StatusBadRequest, fmt.Errorf("нужны segment, enabled и revision текущей конфигурации"))
		return
	}
	v, err := s.app.SetARPBlockIsolation(r.Context(), arpblock.Change{Segment: in.Segment, Enabled: *in.Enabled, Revision: in.Revision})
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, arpblock.ErrConflict) {
			code = http.StatusConflict
		}
		httpErr(w, code, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
