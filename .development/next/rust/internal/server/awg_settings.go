package server

import (
	"net/http"

	"nfqws2strategy/internal/services/awgroute"
)

func (s *Server) awg2SetRecoverySettings(w http.ResponseWriter, r *http.Request) {
	var settings awgroute.RecoverySettings
	if err := readJSON(r, &settings); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.app.AWG2SetRecoverySettings(settings); err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, s.app.AWG2StatusView())
}
