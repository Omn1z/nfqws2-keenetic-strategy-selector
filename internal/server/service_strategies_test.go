package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"nfqws2strategy/internal/services/nfqws2"
)

type serviceCheckRoundTripFunc func(*http.Request) (*http.Response, error)

func (f serviceCheckRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type serviceCheckBody struct {
	io.Reader
	closed bool
}

func (b *serviceCheckBody) Close() error {
	b.closed = true
	return nil
}

type serviceCheckErrorReader struct{ err error }

func (r serviceCheckErrorReader) Read([]byte) (int, error) { return 0, r.err }

func TestNormalizeServiceCheckDomains(t *testing.T) {
	got, err := normalizeServiceCheckDomains([]string{" FacePunch.COM. ", "*.facepunch.com", ".cdn.example", "пример.рф", "xn--e1afmkfd.xn--p1ai"})
	want := []string{"facepunch.com", "cdn.example", "xn--e1afmkfd.xn--p1ai"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized domains %v, error %v; want %v", got, err, want)
	}
	for _, domains := range [][]string{
		nil,
		{"https://facepunch.com/"},
		{"192.0.2.1"},
		{"facepunch.com:443"},
		{"facepunch.com", "bad..example"},
		make([]string, 65),
	} {
		if _, err := normalizeServiceCheckDomains(domains); err == nil {
			t.Errorf("accepted invalid domain request %v", domains)
		}
	}
}

func TestCheckServiceDomainHTTPResponseMeansReachable(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusNoContent, http.StatusForbidden, http.StatusNotFound, http.StatusServiceUnavailable} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			body := &serviceCheckBody{Reader: strings.NewReader("response")}
			calls := 0
			client := &http.Client{Transport: serviceCheckRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodGet || r.URL.String() != "https://facepunch.com/" {
					t.Fatalf("check changed requested endpoint: %s %s", r.Method, r.URL)
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: body, Request: r}, nil
			})}
			result := checkServiceDomain(context.Background(), client, "facepunch.com")
			if !result.OK || result.Domain != "facepunch.com" || result.Detail != fmt.Sprintf("HTTPS: HTTP %d", status) || calls != 1 || !body.closed {
				t.Fatalf("valid HTTP response must establish HTTPS reachability: %+v calls=%d closed=%v", result, calls, body.closed)
			}
		})
	}
}

func TestCheckServiceDomainBrokenResponseAndConnectionErrors(t *testing.T) {
	for _, readErr := range []error{io.ErrUnexpectedEOF, errors.New("response stream interrupted")} {
		t.Run(readErr.Error(), func(t *testing.T) {
			body := &serviceCheckBody{Reader: io.MultiReader(strings.NewReader("partial response"), serviceCheckErrorReader{readErr})}
			client := &http.Client{Transport: serviceCheckRoundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body, Request: r}, nil
			})}
			result := checkServiceDomain(context.Background(), client, "facepunch.com")
			if result.OK || !strings.Contains(result.Detail, readErr.Error()) || !body.closed {
				t.Fatalf("broken response accepted or leaked: %+v closed=%v", result, body.closed)
			}
		})
	}
	client := &http.Client{Transport: serviceCheckRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("TLS handshake failed")
	})}
	if result := checkServiceDomain(context.Background(), client, "facepunch.com"); result.OK || !strings.Contains(result.Detail, "TLS handshake failed") {
		t.Fatalf("connection failure accepted: %+v", result)
	}
}

func TestCheckServiceDomainDoesNotFollowRedirect(t *testing.T) {
	var targets []string
	body := &serviceCheckBody{Reader: strings.NewReader("")}
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: serviceCheckRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			targets = append(targets, r.URL.String())
			return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {"https://different.example/"}}, Body: body, Request: r}, nil
		}),
	}
	result := checkServiceDomain(context.Background(), client, "facepunch.com")
	if !result.OK || result.Detail != "HTTPS: HTTP 302" || result.Domain != "facepunch.com" || !reflect.DeepEqual(targets, []string{"https://facepunch.com/"}) || !body.closed {
		t.Fatalf("redirect changed checked domain: %+v targets=%v closed=%v", result, targets, body.closed)
	}
}

func TestCheckServiceDomainCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &http.Client{Transport: serviceCheckRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if !errors.Is(r.Context().Err(), context.Canceled) {
			t.Fatal("request lost its parent cancellation")
		}
		return nil, r.Context().Err()
	})}
	result := checkServiceDomain(ctx, client, "facepunch.com")
	if result.OK || !strings.Contains(result.Detail, context.Canceled.Error()) {
		t.Fatalf("cancelled check reported success: %+v", result)
	}
}

func TestServiceDomainCheckRouteRejectsInvalidTargets(t *testing.T) {
	s := &Server{}
	mux := http.NewServeMux()
	s.serviceStrategiesRoutes(mux)
	for _, payload := range []string{
		`{"domains":[]}`,
		`{"domains":["https://facepunch.com/"]}`,
		`{"domains":["192.0.2.1"]}`,
		`{"domains":["facepunch.com", "bad..example"]}`,
		`{"domains":`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/api/nfqws2/service-strategies/check", strings.NewReader(payload))
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid input reached checks: status %d body %s", response.Code, response.Body.String())
		}
		var result struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Error == "" {
			t.Fatalf("missing input error: %s, %v", response.Body.String(), err)
		}
	}
}

func TestServiceStrategiesRoutesRejectOversizedBodies(t *testing.T) {
	s := &Server{}
	mux := http.NewServeMux()
	s.serviceStrategiesRoutes(mux)
	for _, test := range []struct{ path, payload string }{
		{"/api/nfqws2/service-strategies/check", `{"domains":["` + strings.Repeat("x", 33<<10) + `"]}`},
		{"/api/nfqws2/service-strategies", `{"services":[],"revision":"` + strings.Repeat("x", (2<<20)+1) + `"}`},
		{"/api/nfqws2/service-strategies/preview", `{"services":[],"revision":"` + strings.Repeat("x", (2<<20)+1) + `"}`},
	} {
		t.Run(test.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(test.payload))
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)
			if response.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("oversized request status %d, body %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestServiceStrategiesErrorMapsStaleRevisionToConflict(t *testing.T) {
	response := httptest.NewRecorder()
	serviceStrategiesError(response, fmt.Errorf("save rejected: %w", nfqws2.ErrServiceStrategiesChanged))
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), nfqws2.ErrServiceStrategiesChanged.Error()) {
		t.Fatalf("stale revision status %d, body %s", response.Code, response.Body.String())
	}
}
