package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDNSMethodRequiresExplicitBoolean(t *testing.T) {
	// Invalid requests must fail before reaching the service: an omitted or
	// misspelled flag cannot silently disable a working DNS method.
	for _, body := range []string{
		`{}`, `{"upstream":"https://dns.example/dns-query","route":"nfqws"}`,
		`{"enabled":null}`, `{"enabled":"false"}`, `{"enabled":0}`, `{`,
	} {
		t.Run(body, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/dnsserver/scheduler/method", strings.NewReader(body))
			(&Server{}).dnsServerMethod(w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("got HTTP %d: %s", w.Code, w.Body.String())
			}
		})
	}
}
