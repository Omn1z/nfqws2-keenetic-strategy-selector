package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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

func updateTestResponse(status int, data string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(data))}
}

func updateTestDigest(data string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(data)))
}

func updateTestBootstrap(tag, manifest string) string {
	return "#!/bin/sh\nPAGES_BASE_URL='" + officialUpdateSite + "'\nRELEASE_TAG='" + tag +
		"'\nSHA256SUMS_SHA256='" + updateTestDigest(manifest) + "'\n"
}

func updateTestManifest(binary string) string {
	return updateTestDigest(binary) + "  nfqws2-strategy-linux-" + runtime.GOARCH + "\n"
}

func TestCheckUpdateOfficialPagesFallback(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{"forbidden", http.StatusForbidden},
		{"rate limited", http.StatusTooManyRequests},
		{"bad gateway", http.StatusBadGateway},
		{"unavailable", http.StatusServiceUnavailable},
		{"network failure", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = original })
			manifest := updateTestManifest("verified binary")
			var requests []string
			budgetDeadline := time.Now().Add(25 * time.Second)
			http.DefaultTransport = selfUpdateRoundTripper(func(r *http.Request) (*http.Response, error) {
				requests = append(requests, r.URL.String())
				gotDeadline, ok := r.Context().Deadline()
				// http.Client adds its earlier 12-second deadline per request;
				// each request must still fit inside the total check budget.
				if !ok || gotDeadline.After(budgetDeadline) || time.Until(gotDeadline) <= 0 {
					t.Fatal("update request has no bounded deadline")
				}
				switch r.URL.String() {
				case "https://api.github.com/repos/" + officialUpdateRepo + "/releases/latest":
					if tc.status == 0 {
						return nil, errors.New("temporary connection failure")
					}
					return updateTestResponse(tc.status, ""), nil
				case officialUpdateSite + "/install.sh":
					return updateTestResponse(http.StatusOK, updateTestBootstrap("v1.8.4", manifest)), nil
				case officialUpdateSite + "/releases/v1.8.4/SHA256SUMS":
					return updateTestResponse(http.StatusOK, manifest), nil
				default:
					t.Fatalf("unexpected update request: %s", r.URL)
					return nil, errors.New("unexpected request")
				}
			})
			a := &App{Cfg: &config.Config{Version: "v1.8.3", Repo: officialUpdateRepo}}
			info, err := a.CheckUpdate()
			if err != nil {
				t.Fatal(err)
			}
			if info.Current != "v1.8.3" || info.Latest != "v1.8.4" || !info.Available || len(requests) != 3 {
				t.Fatalf("unexpected update info/requests: %+v, %v", info, requests)
			}
			if info.assetURL != officialUpdateSite+"/releases/v1.8.4/nfqws2-strategy-linux-"+runtime.GOARCH || info.assetSHA256 != updateTestDigest("verified binary") {
				t.Fatalf("update is not pinned to the verified Pages release: %+v", info)
			}
			data, err := json.Marshal(info)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), officialUpdateSite) || strings.Contains(string(data), info.assetSHA256) {
				t.Fatalf("internal download metadata leaked into JSON: %s", data)
			}
		})
	}
}

func TestCheckUpdateDoesNotUsePagesForCustomReposOrPermanentAPIErrors(t *testing.T) {
	for _, tc := range []struct {
		name, repo string
		status     int
		body       string
	}{
		{"custom forbidden", "example/project", http.StatusForbidden, ""},
		{"custom rate limit", "example/project", http.StatusTooManyRequests, ""},
		{"custom network failure", "example/project", 0, ""},
		{"similar repo", officialUpdateRepo + "-fork", http.StatusForbidden, ""},
		{"not found", officialUpdateRepo, http.StatusNotFound, ""},
		{"invalid JSON", officialUpdateRepo, http.StatusOK, "{"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = original })
			requests := 0
			http.DefaultTransport = selfUpdateRoundTripper(func(r *http.Request) (*http.Response, error) {
				requests++
				if r.URL.Host != "api.github.com" {
					t.Fatalf("unexpected Pages fallback for %s", tc.repo)
				}
				if tc.status == 0 {
					return nil, errors.New("temporary connection failure")
				}
				return updateTestResponse(tc.status, tc.body), nil
			})
			a := &App{Cfg: &config.Config{Version: "v1.8.3", Repo: tc.repo}}
			if info, err := a.CheckUpdate(); err == nil || info.Available || requests != 1 {
				t.Fatalf("unexpected result: %+v, %v, requests=%d", info, err, requests)
			}
		})
	}
}

func TestCheckUpdateAPISuccessSkipsPages(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	requests := 0
	http.DefaultTransport = selfUpdateRoundTripper(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.URL.Host != "api.github.com" {
			t.Fatalf("unnecessary Pages request: %s", r.URL)
		}
		return updateTestResponse(http.StatusOK, `{"tag_name":"v1.8.4","html_url":"https://github.com/official/release"}`), nil
	})
	a := &App{Cfg: &config.Config{Version: "v1.8.3", Repo: officialUpdateRepo}}
	info, err := a.CheckUpdate()
	if err != nil || !info.Available || info.Latest != "v1.8.4" || info.URL != "https://github.com/official/release" || info.assetURL != "" || requests != 1 {
		t.Fatalf("API success changed: %+v, %v, requests=%d", info, err, requests)
	}
}

func TestPagesFallbackPreservesDevelopmentVersionProtection(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	manifest := updateTestManifest("verified binary")
	http.DefaultTransport = selfUpdateRoundTripper(func(r *http.Request) (*http.Response, error) {
		switch r.URL.String() {
		case "https://api.github.com/repos/" + officialUpdateRepo + "/releases/latest":
			return updateTestResponse(http.StatusForbidden, ""), nil
		case officialUpdateSite + "/install.sh":
			return updateTestResponse(http.StatusOK, updateTestBootstrap("v1.8.4", manifest)), nil
		case officialUpdateSite + "/releases/v1.8.4/SHA256SUMS":
			return updateTestResponse(http.StatusOK, manifest), nil
		default:
			t.Fatalf("must not download an older release: %s", r.URL)
			return nil, errors.New("unexpected request")
		}
	})
	for _, current := range []string{"v1.9.0-dev", "v1.8.4", "v1.8.5"} {
		a := &App{Cfg: &config.Config{Version: current, Repo: officialUpdateRepo}}
		info, err := a.SelfUpdate()
		if err == nil || !strings.Contains(err.Error(), "already up to date") || info.Available || info.Current != current || info.Latest != "v1.8.4" {
			t.Fatalf("fallback bypassed version protection: %+v, %v", info, err)
		}
	}
}

func TestParseUpdateBootstrapFailsClosed(t *testing.T) {
	manifest := updateTestManifest("binary")
	valid := updateTestBootstrap("v1.8.4", manifest)
	for _, tc := range []struct {
		name, text string
	}{
		{"duplicate tag", valid + "RELEASE_TAG='v1.8.5'\n"},
		{"empty duplicate", "RELEASE_TAG=''\n" + valid},
		{"export duplicate", valid + "export RELEASE_TAG='v1.8.5'\n"},
		{"double quoted", strings.Replace(valid, "RELEASE_TAG='v1.8.4'", `RELEASE_TAG="v1.8.4"`, 1)},
		{"command substitution", strings.Replace(valid, "RELEASE_TAG='v1.8.4'", "RELEASE_TAG=$(printf v1.8.4)", 1)},
		{"alternate site", strings.Replace(valid, officialUpdateSite, "https://example.com", 1)},
		{"insecure site", strings.Replace(valid, "https://omn1z", "http://omn1z", 1)},
		{"site traversal", strings.Replace(valid, officialUpdateSite, officialUpdateSite+"/../other", 1)},
		{"tag traversal", strings.Replace(valid, "v1.8.4", "v1.8.4/../../other", 1)},
		{"prerelease", strings.Replace(valid, "v1.8.4", "v1.8.4-rc.1", 1)},
		{"leading zero", strings.Replace(valid, "v1.8.4", "v01.8.4", 1)},
		{"missing tag", strings.Replace(valid, "RELEASE_TAG='v1.8.4'\n", "", 1)},
		{"missing hash", strings.Replace(valid, updateTestDigest(manifest), "", 1)},
		{"invalid hash", strings.Replace(valid, updateTestDigest(manifest), strings.Repeat("g", 64), 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parseUpdateBootstrap([]byte(tc.text)); err == nil {
				t.Fatal("accepted invalid bootstrap")
			}
		})
	}
	// The remaining shell body is data, including commands that would have
	// observable side effects if accidentally sourced or executed.
	marker := filepath.Join(t.TempDir(), "must-not-exist")
	valid += "touch '" + marker + "'\n"
	tag, hash, err := parseUpdateBootstrap([]byte(strings.ReplaceAll(valid, "\n", "\r\n")))
	if err != nil || tag != "v1.8.4" || hash != updateTestDigest(manifest) {
		t.Fatalf("valid literal metadata rejected: %q, %q, %v", tag, hash, err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("bootstrap commands must never execute")
	}
}

func TestPagesUpdateRejectsInvalidOrUnpinnedManifest(t *testing.T) {
	valid := updateTestManifest("binary")
	for _, tc := range []struct {
		name, manifest, pinnedManifest string
	}{
		{"tampered", valid, valid + "changed"},
		{"duplicate asset", valid + valid, ""},
		{"duplicate other asset", valid + strings.Repeat("a", 64) + "  install.sh\n" + strings.Repeat("b", 64) + "  install.sh\n", ""},
		{"unsafe path", valid + strings.Repeat("a", 64) + "  ../install.sh\n", ""},
		{"missing asset", strings.Repeat("a", 64) + "  install.sh\n", ""},
		{"malformed hash", strings.Repeat("z", 64) + "  nfqws2-strategy-linux-" + runtime.GOARCH + "\n", ""},
		{"too large", strings.Repeat("x", (1<<20)+1), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pinned := tc.pinnedManifest
			if pinned == "" {
				pinned = tc.manifest
			}
			client := &http.Client{Transport: selfUpdateRoundTripper(func(r *http.Request) (*http.Response, error) {
				switch r.URL.String() {
				case officialUpdateSite + "/install.sh":
					return updateTestResponse(http.StatusOK, updateTestBootstrap("v1.8.4", pinned)), nil
				case officialUpdateSite + "/releases/v1.8.4/SHA256SUMS":
					return updateTestResponse(http.StatusOK, tc.manifest), nil
				default:
					t.Fatalf("unexpected unpinned path: %s", r.URL)
					return nil, errors.New("unexpected request")
				}
			})}
			if info, err := checkPagesUpdate(context.Background(), client); err == nil || info.Latest != "" || info.assetURL != "" {
				t.Fatalf("accepted invalid manifest: %+v, %v", info, err)
			}
		})
	}
}

func TestUpdateMetadataBoundedAndCancellable(t *testing.T) {
	client := &http.Client{Transport: selfUpdateRoundTripper(func(r *http.Request) (*http.Response, error) {
		return updateTestResponse(http.StatusOK, strings.Repeat("x", (256<<10)+1)), nil
	})}
	if _, err := checkPagesUpdate(context.Background(), client); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("unbounded bootstrap: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	client.Transport = selfUpdateRoundTripper(func(r *http.Request) (*http.Response, error) {
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	if _, err := checkPagesUpdate(ctx, client); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("metadata ignored the shared context: %v", err)
	}
}

func TestDownloadSelfUpdateVerifiesPinnedBinary(t *testing.T) {
	for _, valid := range []bool{true, false} {
		t.Run(fmt.Sprintf("valid=%v", valid), func(t *testing.T) {
			original := http.DefaultTransport
			t.Cleanup(func() { http.DefaultTransport = original })
			binary := "verified binary"
			info := UpdateInfo{Latest: "v1.8.4", assetURL: officialUpdateSite + "/releases/v1.8.4/nfqws2-strategy-linux-" + runtime.GOARCH, assetSHA256: updateTestDigest(binary)}
			requests := 0
			http.DefaultTransport = selfUpdateRoundTripper(func(r *http.Request) (*http.Response, error) {
				requests++
				if r.URL.String() != info.assetURL {
					t.Fatalf("used a mutable or unpinned download URL: %s", r.URL)
				}
				if !valid {
					return updateTestResponse(http.StatusOK, "tampered binary"), nil
				}
				return updateTestResponse(http.StatusOK, binary), nil
			})
			dst := filepath.Join(t.TempDir(), "n2s.new")
			err := downloadSelfUpdate(info, officialUpdateRepo, dst)
			if valid {
				data, readErr := os.ReadFile(dst)
				if err != nil || readErr != nil || string(data) != binary {
					t.Fatalf("verified binary failed: %v, %v, %q", err, readErr, data)
				}
			} else if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
				t.Fatalf("tampered binary accepted: %v", err)
			} else if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
				t.Fatal("tampered binary left available for replacement")
			}
			if requests != 1 {
				t.Fatalf("unexpected fallback after binary hash verification: %d requests", requests)
			}
		})
	}
}

func TestUpdateRejectsPlaintextRedirects(t *testing.T) {
	requests := 0
	client := &http.Client{CheckRedirect: selfUpdateHTTPSRedirect, Transport: selfUpdateRoundTripper(func(r *http.Request) (*http.Response, error) {
		requests++
		resp := updateTestResponse(http.StatusFound, "")
		resp.Header.Set("Location", "http://example.com/unverified")
		return resp, nil
	})}
	_, err := readUpdateMetadata(context.Background(), client, officialUpdateSite+"/install.sh", 1024)
	if err == nil || !strings.Contains(err.Error(), "HTTPS") || requests != 1 {
		t.Fatalf("plaintext redirect accepted: %v, requests=%d", err, requests)
	}
	if err := downloadAttempt(client, officialUpdateSite+"/releases/v1.8.4/binary", filepath.Join(t.TempDir(), "binary.part")); err == nil || !strings.Contains(err.Error(), "HTTPS") || requests != 2 {
		t.Fatalf("binary plaintext redirect accepted: %v, requests=%d", err, requests)
	}
}
