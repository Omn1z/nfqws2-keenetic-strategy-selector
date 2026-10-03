package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenWrtDNSRoutesRequireAuthenticationAndCorrectMethods(t *testing.T) {
	s := New(nil)
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/dnsserver/openwrt"},
		{http.MethodPost, "/api/dnsserver/openwrt/apply"},
		{http.MethodPost, "/api/dnsserver/openwrt/restore"},
	} {
		if publicAPI(tc.path) {
			t.Fatalf("OpenWrt mutation state exposed publicly: %s", tc.path)
		}
		_, pattern := s.mux.Handler(httptest.NewRequest(tc.method, tc.path, nil))
		if pattern != tc.method+" "+tc.path {
			t.Fatalf("route missing: %q", pattern)
		}
	}
}

func TestOpenWrtDNSMutationRequiresFreshRevisionBeforeAppAccess(t *testing.T) {
	s := &Server{}
	for _, handler := range []http.HandlerFunc{s.dnsServerOpenWrtApply, s.dnsServerOpenWrtRestore} {
		for _, body := range []string{`{}`, `{"revision":" "}`, `not json`} {
			w := httptest.NewRecorder()
			handler(w, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("unversioned mutation accepted: %d", w.Code)
			}
		}
	}
}
