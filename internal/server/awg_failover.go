package server

import (
	"context"
	"net/http"
	"time"

	"nfqws2strategy/internal/services/awgroute"
)

func (s *Server) awg2SetFailover(w http.ResponseWriter, r *http.Request) {
	var in awgroute.FailoverConfig
	if err := readJSON(r, &in); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.app.AWG2SetFailover(r.PathValue("id"), in); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, s.app.AWG2StatusView())
}

func (s *Server) awg2TestConnection(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, s.app.AWG2TestConnection(ctx, r.PathValue("id")))
}
