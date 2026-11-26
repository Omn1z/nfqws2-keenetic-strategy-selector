package server

import "net/http"

func (s *Server) awg2DiscoveredRoutes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.app.AWG2DiscoveredRoutes())
}
