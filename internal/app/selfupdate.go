package app

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"
)

// UpdateInfo describes the result of an update check.
type UpdateInfo struct {
	Current   string `json:"current"`
	Latest    string `json:"latest"`
	Available bool   `json:"available"`
	URL       string `json:"url"`
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

// SelfUpdate downloads the latest release binary for this architecture, replaces
// the running executable, and triggers a detached service restart. The HTTP
// response returns before the restart fires (the restart is delayed).
func (a *App) SelfUpdate() (UpdateInfo, error) {
	info, err := a.CheckUpdate()
	if err != nil {
		return info, err
	}
	if !info.Available {
		return info, fmt.Errorf("already up to date (%s)", info.Current)
	}
	exe, err := os.Executable()
	if err != nil {
		return info, err
	}
	asset := "nfqws2-strategy-linux-" + runtime.GOARCH
	url := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", a.Cfg.Repo, info.Latest, asset)

	tmp := exe + ".new"
	if err := downloadFile(url, tmp); err != nil {
		_ = os.Remove(tmp)
		return info, fmt.Errorf("download: %w", err)
	}
	if fi, e := os.Stat(tmp); e != nil || fi.Size() < 1_000_000 {
		_ = os.Remove(tmp)
		return info, fmt.Errorf("downloaded file looks invalid")
	}
	_ = os.Chmod(tmp, 0o755)
	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Remove(tmp)
		return info, fmt.Errorf("replace binary: %w", err)
	}
	if err := detachedRestart(a.Cfg.InitScript); err != nil {
		return info, fmt.Errorf("schedule restart: %w", err)
	}
	return info, nil
}

func downloadFile(url, dst string) error {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "nfqws2-strategy")
	resp, err := (&http.Client{Timeout: 120 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}
