package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"nfqws2strategy/internal/services/awgroute"
)

func TestAWGDeleteTransferHTTPNeverDowngradesAnInvalidReplacementToPlainDelete(t *testing.T) {
	for _, query := range []string{"?replacement_id=", "?replacement_id=%20", "?replacement_id=source", "?replacement_id=target&replacement_id=other", "?replacement_id=&replacement_id=target"} {
		t.Run(query, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodDelete, "/api/awg2/servers/source"+query, nil)
			r.SetPathValue("id", "source")
			w := httptest.NewRecorder()
			serveAWG2Delete(w, r, func(string, string) error { t.Fatal("invalid choice invoked deletion"); return nil }, func() awgroute.AWG2Status { t.Fatal("invalid choice read status"); return awgroute.AWG2Status{} })
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d", w.Code)
			}
		})
	}
}

func TestAWGDeleteTransferHTTPPreservesChoiceAndReportsCommittedWarnings(t *testing.T) {
	for _, test := range []struct {
		name, query, target string
		err                 error
		status              int
		warning             bool
	}{
		{name: "legacy deletion", status: http.StatusOK},
		{name: "transfer", query: "?replacement_id=backup%2Ftwo", target: "backup/two", status: http.StatusOK},
		{name: "validation failure", query: "?replacement_id=target", target: "target", err: errors.New("target no longer exists"), status: http.StatusBadRequest},
		{name: "uncertain persistence", query: "?replacement_id=target", target: "target", err: &awgroute.DeleteServerPersistenceUncertainError{Err: errors.New("save and rollback could not be confirmed")}, status: http.StatusConflict},
		{name: "committed runtime failure", query: "?replacement_id=target", target: "target", err: &awgroute.DeleteServerCommittedError{Err: errors.New("saved; routing apply failed")}, status: http.StatusOK, warning: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodDelete, "/api/awg2/servers/source"+test.query, nil)
			r.SetPathValue("id", "source")
			w, calls := httptest.NewRecorder(), 0
			serveAWG2Delete(w, r, func(id, replacement string) error {
				calls++
				if id != "source" || replacement != test.target {
					t.Fatalf("delete choice = %q -> %q", id, replacement)
				}
				return test.err
			}, func() awgroute.AWG2Status {
				if test.status != http.StatusOK {
					t.Fatal("failed operation read status")
				}
				return awgroute.AWG2Status{ActiveID: "target"}
			})
			if calls != 1 || w.Code != test.status {
				t.Fatalf("calls=%d status=%d", calls, w.Code)
			}
			if test.status == http.StatusOK {
				var body map[string]json.RawMessage
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if string(body["active_server_id"]) != `"target"` {
					t.Fatal("response lost the updated status")
				}
				if _, warning := body["warning"]; warning != test.warning {
					t.Fatal("response did not distinguish a committed warning")
				}
			}
		})
	}
}
