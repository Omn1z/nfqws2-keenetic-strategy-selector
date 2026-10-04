package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestShadowRenewEndpointIsPrivatePostAndRequiresConfirmation(t *testing.T) {
	const path = "/api/dnsserver/shadow/renew"
	s := New(nil)
	if publicAPI(path) {
		t.Fatal("WAN action exposed without authentication")
	}
	_, pattern := s.mux.Handler(httptest.NewRequest(http.MethodPost, path, nil))
	if pattern != "POST "+path {
		t.Fatal("POST route missing", pattern)
	}
	_, getPattern := s.mux.Handler(httptest.NewRequest(http.MethodGet, path, nil))
	if getPattern == pattern {
		t.Fatal("GET selected mutation")
	}
	for _, body := range []string{`{}`, `{"confirm":false}`, `{"confirm":"true"}`, `not JSON`} {
		w := httptest.NewRecorder()
		s.dnsServerShadowRenew(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
		if w.Code != http.StatusBadRequest {
			t.Fatal("unconfirmed request reached app", w.Code)
		}
	}
}
