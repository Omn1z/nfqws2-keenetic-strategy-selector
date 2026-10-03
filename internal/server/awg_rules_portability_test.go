package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nfqws2strategy/internal/services/awgroute"
)

func TestRoutingTransferHTTPRejectsDuplicateUnknownAndOversizeBeforeMutation(t *testing.T) {
	server := &Server{} // Invalid bodies must fail before dereferencing App.
	for _, test := range []struct {
		name, body string
		status     int
	}{
		{"duplicate mapping", `{"document":{},"mode":"append","mappings":{"one":"a","one":"b"}}`, 400},
		{"unknown field", `{"document":{},"mode":"append","private_key":"secret"}`, 400},
		{"trailing JSON", `{"document":{},"mode":"append"}{}`, 400},
		{"oversize", strings.Repeat(" ", awgroute.AWGRoutingRequestLimit+1), 413},
	} {
		t.Run(test.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/api/awg2/routing/rules/import", strings.NewReader(test.body))
			server.awg2RulesImport(w, r)
			if w.Code != test.status {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/awg2/routing/rules/export", strings.NewReader(`{"routing":null}`))
	server.awg2RulesExport(w, r)
	if w.Code != 400 {
		t.Fatal("missing draft allowed")
	}
}

func TestRoutingTransferHTTPConflictAndJSONDTO(t *testing.T) {
	w := httptest.NewRecorder()
	awgRoutingTransferError(w, awgroute.ErrAWGRoutingPolicyConflict)
	if w.Code != 409 {
		t.Fatal("policy race must require repreview")
	}
	w = httptest.NewRecorder()
	awgRoutingTransferError(w, errors.New("validation"))
	if w.Code != 400 {
		t.Fatal("validation status")
	}
	var request awgroute.AWGRoutingImportRequest
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"document":"{}","mode":"append","mappings":{"one":"target"},"mapping_fingerprints":{"one":"fingerprint"},"expected_policy_hash":"policy","base_routing":{"mode":"zones","zones":[],"mtu":1420,"killswitch":false,"domain_source":"dnsproxy","sni_routing":false,"trace_enabled":false,"active":false}}`))
	if err := readAWGRoutingTransferJSON(httptest.NewRecorder(), r, &request); err != nil || request.ExpectedPolicyHash != "policy" || request.BaseRouting == nil || request.Mappings["one"] != "target" {
		t.Fatal("UI import DTO rejected", err)
	}
}
