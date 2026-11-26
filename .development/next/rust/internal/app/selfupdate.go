package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"nfqws2strategy/internal/tools/logbuf"
	"nfqws2strategy/internal/tools/modules"
)

// UpdateInfo describes the result of an update check.
type UpdateInfo struct {
	Current   string `json:"current"`
	Latest    string `json:"latest"`
	Available bool   `json:"available"`
	URL       string `json:"url"`

	// A Pages fallback is pinned to the verified bootstrap's release and
	// checksum. These details are internal to this check/update operation.
	assetURL    string
	assetSHA256 string
}

const (
	officialUpdateRepo = "Omn1z/nfqws2-keenetic-strategy-selector"
	officialUpdateSite = "https://omn1z.github.io/nfqws2-keenetic-strategy-selector"
)

// SelfUpdateStatus is the observable state of a UI-triggered self-update.
type SelfUpdateStatus struct {
	Running    bool   `json:"running"`
	Current    string `json:"current"`
	Latest     string `json:"latest"`
	Stage      string `json:"stage"`
	Error      string `json:"error,omitempty"`
	StartedAt  int64  `json:"started_at"`
	FinishedAt int64  `json:"finished_at,omitempty"`
}

// CheckUpdate prefers GitHub Releases, with the official verified Pages mirror
// as a fallback when the API is rate limited or temporarily unavailable.
func (a *App) CheckUpdate() (UpdateInfo, error) {
	if modules.Compact {
		return UpdateInfo{Current: a.Cfg.Version}, fmt.Errorf("компактная панель обновляется через репозиторий Entware (opkg)")
	}
	return a.checkReleaseUpdate()
}

func (a *App) checkReleaseUpdate() (UpdateInfo, error) {
	info := UpdateInfo{Current: a.Cfg.Version}
	if a.Cfg.Repo == "" {
		return info, fmt.Errorf("repo not configured")
	}
	// The UI's read timeout is 30 seconds. Share one budget across the API,
	// bootstrap and manifest rather than spending a fresh timeout on each.
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 12 * time.Second, CheckRedirect: selfUpdateHTTPSRedirect}
	latest, releaseURL, canFallback, err := checkGitHubUpdate(ctx, client, a.Cfg.Repo)
	if err != nil {
		if !canFallback || !strings.EqualFold(a.Cfg.Repo, officialUpdateRepo) {
			return info, err
		}
		fallback, fallbackErr := checkPagesUpdate(ctx, client)
		if fallbackErr != nil {
			return info, fmt.Errorf("%w; official Pages fallback: %v", err, fallbackErr)
		}
		info = fallback
		info.Current = a.Cfg.Version
	} else {
		info.Latest = latest
		info.URL = releaseURL
	}
	info.Available = selfUpdateAvailable(a.Cfg.Version, info.Latest)
	return info, nil
}

func checkGitHubUpdate(ctx context.Context, client *http.Client, repo string) (tag, releaseURL string, canFallback bool, err error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/repos/"+repo+"/releases/latest", nil)
	if err != nil {
		return "", "", false, err
	}
	req.Header.Set("User-Agent", "nfqws2-strategy")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return "", "", true, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		canFallback = resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 500 && resp.StatusCode < 600)
		return "", "", canFallback, fmt.Errorf("github api status %d", resp.StatusCode)
	}
	var rel struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return "", "", false, err
	}
	return rel.TagName, rel.HTMLURL, false, nil
}

func selfUpdateHTTPSRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("too many update redirects")
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("update redirect must use HTTPS")
	}
	return nil
}

func readUpdateMetadata(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nfqws2-strategy")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || int64(len(data)) > limit {
		return nil, fmt.Errorf("update metadata is empty or too large")
	}
	return data, nil
}

// The Pages publisher writes these three literal assignments after verifying
// the original release assets. Treat the bootstrap solely as bounded data;
// never source it or execute any of its commands.
func parseUpdateBootstrap(data []byte) (tag, manifestSHA256 string, err error) {
	values := make(map[string]string)
	literal := regexp.MustCompile(`^(PAGES_BASE_URL|RELEASE_TAG|SHA256SUMS_SHA256)='([^'\r\n]*)'$`)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		name, _, assignment := strings.Cut(line, "=")
		name = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(name), "export "))
		if !assignment || (name != "PAGES_BASE_URL" && name != "RELEASE_TAG" && name != "SHA256SUMS_SHA256") {
			continue
		}
		match := literal.FindStringSubmatch(line)
		_, exists := values[name]
		if match == nil || exists {
			return "", "", fmt.Errorf("invalid or duplicate bootstrap assignment: %s", name)
		}
		values[name] = match[2]
	}
	if values["PAGES_BASE_URL"] != officialUpdateSite {
		return "", "", fmt.Errorf("invalid bootstrap Pages URL")
	}
	tag = values["RELEASE_TAG"]
	if !regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`).MatchString(tag) || len(tag) > 64 || !semver.IsValid(tag) {
		return "", "", fmt.Errorf("invalid bootstrap release tag")
	}
	manifestSHA256 = values["SHA256SUMS_SHA256"]
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(manifestSHA256) {
		return "", "", fmt.Errorf("invalid bootstrap checksum")
	}
	return tag, manifestSHA256, nil
}

func parseUpdateChecksums(data []byte, asset string) (string, error) {
	checksums := make(map[string]string)
	entry := regexp.MustCompile(`^([0-9a-fA-F]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._-]*)$`)
	for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		match := entry.FindStringSubmatch(strings.TrimSuffix(line, "\r"))
		if match == nil {
			return "", fmt.Errorf("invalid update checksum entry")
		}
		if _, exists := checksums[match[2]]; exists {
			return "", fmt.Errorf("duplicate update checksum entry")
		}
		checksums[match[2]] = strings.ToLower(match[1])
	}
	if checksums[asset] == "" {
		return "", fmt.Errorf("missing update checksum for %s", asset)
	}
	return checksums[asset], nil
}

func checkPagesUpdate(ctx context.Context, client *http.Client) (UpdateInfo, error) {
	var info UpdateInfo
	bootstrap, err := readUpdateMetadata(ctx, client, officialUpdateSite+"/install.sh", 256<<10)
	if err != nil {
		return info, err
	}
	tag, manifestSHA256, err := parseUpdateBootstrap(bootstrap)
	if err != nil {
		return info, err
	}
	releaseURL := officialUpdateSite + "/releases/" + tag
	manifest, err := readUpdateMetadata(ctx, client, releaseURL+"/SHA256SUMS", 1<<20)
	if err != nil {
		return info, err
	}
	if fmt.Sprintf("%x", sha256.Sum256(manifest)) != manifestSHA256 {
		return info, fmt.Errorf("update checksum manifest SHA-256 mismatch")
	}
	asset := "nfqws2-strategy-linux-" + runtime.GOARCH
	assetSHA256, err := parseUpdateChecksums(manifest, asset)
	if err != nil {
		return info, err
	}
	info.Latest = tag
	info.URL = "https://github.com/" + officialUpdateRepo + "/releases/tag/" + tag
	info.assetURL = releaseURL + "/" + asset
	info.assetSHA256 = assetSHA256
	return info, nil
}

// selfUpdateAvailable preserves the numeric version of development builds:
// v1.6.0-dev can upgrade to v1.6.0, but must not be replaced by v1.5.0.
// Unversioned local builds ("dev", a commit hash, etc.) can install a release.
func selfUpdateAvailable(current, latest string) bool {
	currentVersion, currentRevision := selfUpdateVersion(current)
	latestVersion, latestRevision := selfUpdateVersion(latest)
	if latestVersion == "" {
		return false
	}
	if currentVersion == "" {
		return true
	}
	if cmp := semver.Compare(latestVersion, currentVersion); cmp != 0 {
		return cmp > 0
	}
	return latestRevision > currentRevision
}

func selfUpdateVersion(version string) (string, string) {
	version = strings.TrimSpace(version)
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	if semver.IsValid(version) {
		return version, ""
	}
	// Historical release tags v1.4.1a and v1.4.1b were fixes published after
	// v1.4.1. Keep that ordering without interpreting them as prereleases.
	base := strings.TrimRight(version, "abcdefghijklmnopqrstuvwxyz")
	if base != version && strings.Count(base, ".") == 2 && !strings.ContainsAny(base, "-+") && semver.IsValid(base) {
		return base, strings.TrimPrefix(version, base)
	}
	return "", ""
}

// StartSelfUpdate starts a background self-update and returns immediately. The
// web UI uses this so a slow download never pins the browser request.
func (a *App) StartSelfUpdate() (SelfUpdateStatus, error) {
	if modules.Compact {
		return a.SelfUpdateStatus(), fmt.Errorf("обновите компактную панель и её модули через Entware")
	}
	a.selfUpdateMu.Lock()
	if a.selfUpdate.Running {
		st := a.selfUpdate
		a.selfUpdateMu.Unlock()
		return st, nil
	}
	now := time.Now().Unix()
	a.selfUpdate = SelfUpdateStatus{
		Running:   true,
		Current:   a.Cfg.Version,
		Stage:     "queued",
		StartedAt: now,
	}
	st := a.selfUpdate
	a.selfUpdateMu.Unlock()

	go a.runSelfUpdateJob()
	return st, nil
}

func (a *App) SelfUpdateStatus() SelfUpdateStatus {
	a.selfUpdateMu.Lock()
	defer a.selfUpdateMu.Unlock()
	st := a.selfUpdate
	if st.Current == "" {
		st.Current = a.Cfg.Version
		st.Stage = "idle"
	}
	return st
}

func (a *App) runSelfUpdateJob() {
	logbuf.Append("update", "info", "self-update started")
	info, err := a.selfUpdateWithProgress(func(stage string, info UpdateInfo) {
		a.setSelfUpdateStatus(func(st *SelfUpdateStatus) {
			st.Stage = stage
			if info.Current != "" {
				st.Current = info.Current
			}
			if info.Latest != "" {
				st.Latest = info.Latest
			}
			st.Error = ""
		})
	})
	if err != nil {
		msg := err.Error()
		logbuf.Append("update", "error", "self-update failed: "+msg)
		a.setSelfUpdateStatus(func(st *SelfUpdateStatus) {
			st.Running = false
			st.Stage = "error"
			st.Error = msg
			st.FinishedAt = time.Now().Unix()
			if info.Current != "" {
				st.Current = info.Current
			}
			if info.Latest != "" {
				st.Latest = info.Latest
			}
		})
		return
	}
	logbuf.Append("update", "info", "self-update scheduled restart: "+info.Current+" -> "+info.Latest)
	a.setSelfUpdateStatus(func(st *SelfUpdateStatus) {
		st.Running = false
		st.Stage = "restarting"
		st.Error = ""
		st.FinishedAt = time.Now().Unix()
		st.Current = info.Current
		st.Latest = info.Latest
	})
}

func (a *App) setSelfUpdateStatus(fn func(*SelfUpdateStatus)) {
	a.selfUpdateMu.Lock()
	defer a.selfUpdateMu.Unlock()
	fn(&a.selfUpdate)
}

// SelfUpdate downloads the latest release binary for this architecture, replaces
// the running executable, and triggers a detached service restart. The HTTP
// response returns before the restart fires (the restart is delayed).
func (a *App) SelfUpdate() (UpdateInfo, error) {
	if modules.Compact {
		return a.CheckUpdate()
	}
	return a.selfUpdateWithProgress(nil)
}

func (a *App) selfUpdateWithProgress(progress func(string, UpdateInfo)) (UpdateInfo, error) {
	if progress != nil {
		progress("checking", UpdateInfo{Current: a.Cfg.Version})
	}
	info, err := a.checkReleaseUpdate()
	if err != nil {
		return info, err
	}
	if progress != nil {
		progress("checked", info)
	}
	if !info.Available {
		return info, fmt.Errorf("already up to date (%s)", info.Current)
	}
	exe, err := os.Executable()
	if err != nil {
		return info, err
	}
	tmp := exe + ".new"
	if progress != nil {
		progress("downloading", info)
	}
	if err := downloadSelfUpdate(info, a.Cfg.Repo, tmp); err != nil {
		_ = os.Remove(tmp)
		return info, fmt.Errorf("download: %w", err)
	}
	if fi, e := os.Stat(tmp); e != nil || fi.Size() < 1_000_000 {
		_ = os.Remove(tmp)
		return info, fmt.Errorf("downloaded file looks invalid")
	}
	if progress != nil {
		progress("replacing", info)
	}
	_ = os.Chmod(tmp, 0o755)
	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Remove(tmp)
		return info, fmt.Errorf("replace binary: %w", err)
	}
	if progress != nil {
		progress("restarting", info)
	}
	if err := detachedRestart(a.Cfg.InitScript); err != nil {
		return info, fmt.Errorf("schedule restart: %w", err)
	}
	return info, nil
}

func downloadSelfUpdate(info UpdateInfo, repo, dst string) error {
	asset := "nfqws2-strategy-linux-" + runtime.GOARCH
	urls := []string{
		fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", repo, info.Latest, asset),
		fmt.Sprintf("https://github.com/%s/releases/latest/download/%s", repo, asset),
	}
	if info.assetURL != "" {
		if info.assetSHA256 == "" {
			return fmt.Errorf("missing pinned update checksum")
		}
		// Never use a mutable latest URL for a hash-pinned Pages update.
		urls = []string{info.assetURL}
	}
	if err := downloadFile(urls, dst); err != nil {
		return err
	}
	if info.assetSHA256 != "" {
		f, err := os.Open(dst)
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, hashErr := io.Copy(hash, f)
		closeErr := f.Close()
		if hashErr != nil {
			return hashErr
		}
		if closeErr != nil {
			return closeErr
		}
		if fmt.Sprintf("%x", hash.Sum(nil)) != info.assetSHA256 {
			_ = os.Remove(dst)
			return fmt.Errorf("update binary SHA-256 mismatch")
		}
	}
	return nil
}

func downloadFile(urls []string, dst string) error {
	if len(urls) == 0 {
		return fmt.Errorf("no download urls")
	}
	var lastErr error
	for _, url := range urls {
		if strings.TrimSpace(url) == "" {
			continue
		}
		if err := downloadWithRetry(url, dst); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no usable download urls")
	}
	return lastErr
}

func downloadWithRetry(url, dst string) error {
	part := dst + ".part"
	_ = os.Remove(part)
	client := &http.Client{Timeout: 180 * time.Second, CheckRedirect: selfUpdateHTTPSRedirect}
	var lastErr error
	for attempt := 1; attempt <= 5; attempt++ {
		err := downloadAttempt(client, url, part)
		if err == nil {
			if err := os.Rename(part, dst); err != nil {
				return err
			}
			return nil
		}
		lastErr = err
		if attempt < 5 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
	_ = os.Remove(part)
	return lastErr
}

func downloadAttempt(client *http.Client, url, part string) error {
	var offset int64
	if st, err := os.Stat(part); err == nil {
		offset = st.Size()
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "nfqws2-strategy")
	req.Header.Set("Cache-Control", "no-cache")
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch {
	case offset > 0 && resp.StatusCode == http.StatusPartialContent:
		// resume
	case resp.StatusCode == http.StatusOK:
		offset = 0
	default:
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	flag := os.O_CREATE | os.O_WRONLY
	if offset > 0 {
		flag |= os.O_APPEND
	} else {
		flag |= os.O_TRUNC
	}
	f, err := os.OpenFile(part, flag, 0o755)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, resp.Body)
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
