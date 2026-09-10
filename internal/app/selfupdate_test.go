package app

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nfqws2strategy/internal/tools/config"
)

func TestSelfUpdateAvailable(t *testing.T) {
	tests := []struct {
		name, current, latest string
		want                  bool
	}{
		{"newer stable", "v1.5.0", "v1.6.0", true},
		{"older stable", "v1.6.0", "v1.5.0", false},
		{"same stable", "v1.6.0", "v1.6.0", false},
		{"newer development build", "v1.6.0-dev", "v1.5.0", false},
		{"development to matching release", "v1.6.0-dev", "v1.6.0", true},
		{"development to later release", "v1.6.0-dev", "v1.6.1", true},
		{"stable to matching prerelease", "v1.6.0", "v1.6.0-rc.1", false},
		{"numeric minor comparison", "v1.9.0", "v1.10.0", true},
		{"numeric patch comparison", "v1.3.19", "v1.3.9", false},
		{"numeric prerelease comparison", "v1.6.0-rc.2", "v1.6.0-rc.10", true},
		{"build metadata ignored", "v1.6.0+local", "v1.6.0+release", false},
		{"optional prefix", "1.6.0", "v1.6.0", false},
		{"whitespace", " v1.6.0-dev ", " v1.6.0 ", true},
		{"unversioned development", "dev", "v1.5.0", true},
		{"unversioned commit", "c37a0f4", "v1.5.0", true},
		{"empty build version", "", "v1.5.0", true},
		{"missing latest", "v1.5.0", "", false},
		{"invalid latest", "v1.5.0", "broken-release", false},
		{"invalid latest and development", "dev", "broken-release", false},
		{"legacy first revision", "v1.4.1", "v1.4.1a", true},
		{"legacy later revision", "v1.4.1a", "v1.4.1b", true},
		{"legacy older revision", "v1.4.1b", "v1.4.1a", false},
		{"legacy same revision", "v1.4.1b", "v1.4.1b", false},
		{"legacy base is older", "v1.4.1b", "v1.4.1", false},
		{"legacy to next patch", "v1.4.1b", "v1.4.2", true},
		{"next patch to legacy", "v1.4.2", "v1.4.1b", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := selfUpdateAvailable(tt.current, tt.latest); got != tt.want {
				t.Fatalf("selfUpdateAvailable(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
			}
		})
	}
}

type selfUpdateRoundTripper func(*http.Request) (*http.Response, error)

func (f selfUpdateRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestCheckUpdateDoesNotOfferOlderReleaseToVersionedDevelopmentBuild(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	requests := 0
	http.DefaultTransport = selfUpdateRoundTripper(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.URL.String() != "https://api.github.com/repos/example/project/releases/latest" {
			t.Fatalf("unexpected update request: %s", r.URL)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"tag_name":"v1.5.0","html_url":"https://github.com/example/project/releases/tag/v1.5.0"}`)),
		}, nil
	})
	a := &App{Cfg: &config.Config{Version: "v1.6.0-dev", Repo: "example/project"}}
	info, err := a.CheckUpdate()
	if err != nil {
		t.Fatal(err)
	}
	if info.Current != "v1.6.0-dev" || info.Latest != "v1.5.0" || info.Available {
		t.Fatalf("unexpected update info: %+v", info)
	}
	if _, err := a.SelfUpdate(); err == nil || !strings.Contains(err.Error(), "already up to date") {
		t.Fatalf("SelfUpdate should stop before downloading an older release, got %v", err)
	}
	if requests != 2 {
		t.Fatalf("got %d requests, want only two release checks and no asset download", requests)
	}
}

func TestDownloadFileRetriesAfterTemporaryFailure(t *testing.T) {
	attempts := 0
	want := []byte("release-binary")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			http.Error(w, "temporary reset stand-in", http.StatusBadGateway)
			return
		}
		_, _ = w.Write(want)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "n2s.new")
	if err := downloadFile([]string{srv.URL}, dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("downloaded %q, want %q", got, want)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestDownloadFileFallsBackToSecondURL(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "blocked", http.StatusForbidden)
	}))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer good.Close()

	dst := filepath.Join(t.TempDir(), "n2s.new")
	if err := downloadFile([]string{bad.URL, good.URL}, dst); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ok" {
		t.Fatalf("downloaded %q, want ok", got)
	}
}
