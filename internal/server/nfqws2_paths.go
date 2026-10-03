package server

import "net/http"

func (s *Server) nfqws2Paths(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	var in struct {
		Content string `json:"content"`
		Kind    string `json:"kind"`
	}
	if err := readJSON(r, &in); err != nil {
		httpErr(w, 400, err)
		return
	}
	if in.Kind != "lua" {
		in.Kind = "conf"
	}
	writeJSON(w, 200, s.app.AnalyzeNfqws2Paths(in.Content, in.Kind))
}
