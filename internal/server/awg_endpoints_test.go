package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"nfqws2strategy/internal/services/awgroute"
)

func TestAWGEndpointBackupsHTTPRequiresExplicitList(t *testing.T) {
	for _, body := range []string{`{}`, `{"endpoint_backups":null}`, `{"endpoint_backups":"192.0.2.2"}`, `{`} {
		t.Run(body, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
			r.SetPathValue("id", "server")
			w := httptest.NewRecorder()
			serveAWG2EndpointBackups(w, r, func(string, []string) error { t.Fatal("invalid request changed settings"); return nil }, func() awgroute.AWG2Status { t.Fatal("invalid request read status"); return awgroute.AWG2Status{} })
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d", w.Code)
			}
		})
	}
}

func TestAWGEndpointBackupsHTTPPreservesOrderAndExplicitClear(t *testing.T) {
	for _, endpoints := range [][]string{{"192.0.2.2", "[2001:db8::2]:443"}, {}} {
		body := `{"endpoint_backups":[]}`
		if len(endpoints) > 0 {
			body = `{"endpoint_backups":["192.0.2.2","[2001:db8::2]:443"]}`
		}
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		r.SetPathValue("id", "specific-server")
		w, calls := httptest.NewRecorder(), 0
		serveAWG2EndpointBackups(w, r, func(id string, got []string) error {
			calls++
			if id != "specific-server" || !slices.Equal(got, endpoints) {
				t.Fatalf("save = %q, %v", id, got)
			}
			return nil
		}, func() awgroute.AWG2Status { return awgroute.AWG2Status{ActiveID: "specific-server"} })
		if calls != 1 || w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"active_server_id":"specific-server"`) {
			t.Fatalf("calls=%d status=%d body=%s", calls, w.Code, w.Body.String())
		}
	}
}

func TestAWGEndpointBackupsHTTPReportsSaveFailure(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"endpoint_backups":[]}`))
	r.SetPathValue("id", "missing")
	w := httptest.NewRecorder()
	serveAWG2EndpointBackups(w, r, func(string, []string) error { return errors.New("unknown connection") }, func() awgroute.AWG2Status { t.Fatal("failed save read status"); return awgroute.AWG2Status{} })
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "unknown connection") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestAWGEndpointBackupsHTTPDistinguishesCommittedWarningAndUncertainStorage(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		code int
	}{
		{"committed routing warning", &awgroute.EndpointBackupsCommittedError{Err: errors.New("route restore failed")}, http.StatusOK},
		{"uncertain storage", &awgroute.EndpointBackupsPersistenceUncertainError{Err: errors.New("write and rollback failed")}, http.StatusConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"endpoint_backups":[]}`))
			r.SetPathValue("id", "server")
			w := httptest.NewRecorder()
			serveAWG2EndpointBackups(w, r, func(string, []string) error { return test.err }, func() awgroute.AWG2Status {
				if test.code != http.StatusOK {
					t.Fatal("uncertain write returned success status")
				}
				return awgroute.AWG2Status{ActiveID: "server"}
			})
			if w.Code != test.code || strings.Contains(w.Body.String(), `"warning":`) != (test.code == http.StatusOK) {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}
