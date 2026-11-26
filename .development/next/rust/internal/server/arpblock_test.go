package server

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestARPBlockMutationRequiresExplicitBooleanAndRevision(t *testing.T) {
	revision := strings.Repeat("a", 64)
	for _, body := range []string{
		`{}`,
		`{"segment":"Bridge0","revision":"` + revision + `"}`,
		`{"segment":"Bridge0","enabled":null,"revision":"` + revision + `"}`,
		`{"segment":"Bridge0","enabled":"false","revision":"` + revision + `"}`,
		`{"segment":"Bridge0","enabled":false,"revision":"short"}`,
		`{"segment":"Bridge0","enabled":false,"revision":"` + revision + `","unexpected":true}`,
		`{"segment":"Bridge0","enabled":false,"revision":"` + revision + `"} {}`,
		`{"segment":"` + strings.Repeat("a", 2100) + `","enabled":false,"revision":"` + revision + `"}`,
	} {
		r := httptest.NewRequest("POST", "/api/arp-block/isolation", strings.NewReader(body))
		w := httptest.NewRecorder()
		// No app: invalid input must be rejected before it can access the service.
		(&Server{}).setARPBlockIsolation(w, r)
		if w.Code != 400 {
			t.Fatalf("accepted invalid mutation: %d", w.Code)
		}
	}
}
