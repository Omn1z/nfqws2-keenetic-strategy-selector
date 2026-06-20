package app

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"nfqws2strategy/internal/tools/logbuf"
)

// UpdateInfo describes the result of an update check.
type UpdateInfo struct {
	Current   string `json:"current"`
	Latest    string `json:"latest"`
	Available bool   `json:"available"`
	URL       string `json:"url"`
}

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

// CheckUpdate queries the GitHub Releases API for the latest tag.
func (a *App) CheckUpdate() (UpdateInfo, error) {
	info := UpdateInfo{Current: a.Cfg.Version}
	if a.Cfg.Repo == "" {
		return info, fmt.Errorf("repo not configured")
	}
	req, _ := http.NewRequest("GET", "https://api.github.com/repos/"+a.Cfg.Repo+"/releases/latest", nil)
	req.Header.Set("User-Agent", "nfqws2-strategy")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := (&http.Client{Timeout: 12 * time.Second}).Do(req)
	if err != nil {
		return info, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return info, fmt.Errorf("github api status %d", resp.StatusCode)
	}
	var rel struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return info, err
	}
	info.Latest = rel.TagName
	info.URL = rel.HTMLURL
	info.Available = rel.TagName != "" && rel.TagName != a.Cfg.Version
	return info, nil
}

// StartSelfUpdate starts a background self-update and returns immediately. The
// web UI uses this so a slow download never pins the browser request.
func (a *App) StartSelfUpdate() (SelfUpdateStatus, error) {
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
	return a.selfUpdateWithProgress(nil)
}

func (a *App) selfUpdateWithProgress(progress func(string, UpdateInfo)) (UpdateInfo, error) {
	if progress != nil {
		progress("checking", UpdateInfo{Current: a.Cfg.Version})
	}
	info, err := a.CheckUpdate()
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
	asset := "nfqws2-strategy-linux-" + runtime.GOARCH
	urls := []string{
		fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", a.Cfg.Repo, info.Latest, asset),
		fmt.Sprintf("https://github.com/%s/releases/latest/download/%s", a.Cfg.Repo, asset),
	}

	tmp := exe + ".new"
	if progress != nil {
		progress("downloading", info)
	}
	if err := downloadFile(urls, tmp); err != nil {
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
	client := &http.Client{Timeout: 180 * time.Second}
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
