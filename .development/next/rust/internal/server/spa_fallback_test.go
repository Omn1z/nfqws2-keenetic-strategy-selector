package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSPAFallbackRejectsRemovedAndUnknownAPI(t *testing.T) {
	s := &Server{}
	for _, path := range []string{"/api", "/api/pihole/status", "/api/pihole/install", "/api/unknown"} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			w := httptest.NewRecorder()
			s.serveIndex(w, httptest.NewRequest(method, path, nil))
			if w.Code != http.StatusNotFound {
				t.Fatalf("%s %s: status %d, want 404", method, path, w.Code)
			}
			if strings.Contains(w.Header().Get("Content-Type"), "text/html") {
				t.Fatalf("%s %s returned the SPA instead of an API error", method, path)
			}
		}
	}
}

func TestSPAFallbackKeepsBrowserDeepLinks(t *testing.T) {
	w := httptest.NewRecorder()
	(&Server{}).serveIndex(w, httptest.NewRequest(http.MethodGet, "/dnsserver", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("browser route: status %d, content type %q", w.Code, w.Header().Get("Content-Type"))
	}
}
