package app

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"nfqws2strategy/internal/tools/geo"
)

const geoAutoFile = "geo_auto.json"

// Default upstream releases. Loyalsoldier publishes a daily auto-build of both
// files with broader RU/CN/Apple coverage than upstream v2fly, and — unlike
// v2fly/domain-list-community which only puts dlc.dat into the `release` branch
// — these are real GitHub release assets so the "/latest/download/" alias works.
const (
	defaultGeoSiteURL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
	defaultGeoIPURL   = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"

	defaultGeoIntervalHours = 24
	geoFetchTimeout         = 5 * time.Minute  // big files over a slow LTE WAN
	geoFetchMinInterval     = 15 * time.Minute // floor between manual fetches, protects upstream + LTE quota
)

// GeoAutoConfig is the persistent auto-update configuration. Stored separately
// from per-server AWG config because the geo files are GLOBAL — they belong to
// the panel, not to a single VPN endpoint.
type GeoAutoConfig struct {
	Enabled        bool   `json:"enabled"`
	GeoSiteURL     string `json:"geosite_url"`
	GeoIPURL       string `json:"geoip_url"`
	IntervalHours  int    `json:"interval_hours"`
	LastFetchedAt  int64  `json:"last_fetched_at"`
	LastError      string `json:"last_error"`
	LastGeoSiteAt  int64  `json:"last_geosite_at"`
	LastGeoIPAt    int64  `json:"last_geoip_at"`
	LastGeoSiteLen int64  `json:"last_geosite_len"`
	LastGeoIPLen   int64  `json:"last_geoip_len"`
}

func defaultGeoAuto() *GeoAutoConfig {
	return &GeoAutoConfig{
		Enabled:       false,
		GeoSiteURL:    defaultGeoSiteURL,
		GeoIPURL:      defaultGeoIPURL,
		IntervalHours: defaultGeoIntervalHours,
	}
}

type geoAutoState struct {
	mu      sync.Mutex
	last    time.Time
	stop    chan struct{}
	running bool
}

// GeoAuto returns the current auto-update configuration (creating defaults on
// first call).
func (a *App) GeoAuto() *GeoAutoConfig {
	cfg := defaultGeoAuto()
	_ = a.store.Load(geoAutoFile, cfg)
	if cfg.GeoSiteURL == "" {
		cfg.GeoSiteURL = defaultGeoSiteURL
	}
	if cfg.GeoIPURL == "" {
		cfg.GeoIPURL = defaultGeoIPURL
	}
	if cfg.IntervalHours <= 0 {
		cfg.IntervalHours = defaultGeoIntervalHours
	}
	return cfg
}

// SetGeoAuto persists a new auto-update config. The background ticker re-reads
// it on its next tick, so changes apply without a restart.
func (a *App) SetGeoAuto(in *GeoAutoConfig) error {
	cfg := defaultGeoAuto()
	if in != nil {
		cfg = in
	}
	if cfg.IntervalHours <= 0 {
		cfg.IntervalHours = defaultGeoIntervalHours
	}
	if strings.TrimSpace(cfg.GeoSiteURL) == "" {
		cfg.GeoSiteURL = defaultGeoSiteURL
	}
	if strings.TrimSpace(cfg.GeoIPURL) == "" {
		cfg.GeoIPURL = defaultGeoIPURL
	}
	a.geoAuto.mu.Lock()
	defer a.geoAuto.mu.Unlock()
	current := a.GeoAuto()
	current.Enabled, current.IntervalHours = cfg.Enabled, cfg.IntervalHours
	current.GeoSiteURL, current.GeoIPURL = cfg.GeoSiteURL, cfg.GeoIPURL
	return a.store.Save(geoAutoFile, current)
}

// FetchGeoNow runs one synchronous fetch cycle and updates the persisted status.
// Errors from individual downloads are recorded in LastError but never block the
// other kind (geosite failure does not skip geoip and vice versa).
func (a *App) FetchGeoNow() (*GeoAutoConfig, error) {
	cfg := a.GeoAuto()
	if !geoModuleAvailable() {
		err := fmt.Errorf("модуль GeoSite/GeoIP не установлен")
		cfg.LastError = err.Error()
		return cfg, err
	}
	a.geoAuto.mu.Lock()
	since := time.Since(a.geoAuto.last)
	if since > 0 && since < geoFetchMinInterval {
		a.geoAuto.mu.Unlock()
		return cfg, fmt.Errorf("слишком часто: подождите %s между запросами", geoFetchMinInterval-since)
	}
	a.geoAuto.last = time.Now()
	a.geoAuto.mu.Unlock()

	var errs []string
	if u := strings.TrimSpace(cfg.GeoSiteURL); u != "" {
		if size, err := a.fetchGeoFile(u, "geosite.dat", geo.KindGeoSite); err != nil {
			errs = append(errs, "geosite: "+err.Error())
		} else {
			cfg.LastGeoSiteAt = time.Now().Unix()
			cfg.LastGeoSiteLen = size
		}
	}
	if u := strings.TrimSpace(cfg.GeoIPURL); u != "" {
		if size, err := a.fetchGeoFile(u, "geoip.dat", geo.KindGeoIP); err != nil {
			errs = append(errs, "geoip: "+err.Error())
		} else {
			cfg.LastGeoIPAt = time.Now().Unix()
			cfg.LastGeoIPLen = size
		}
	}
	// Keep settings edited while either HTTP request was in flight.
	a.geoAuto.mu.Lock()
	defer a.geoAuto.mu.Unlock()
	current := a.GeoAuto()
	current.LastGeoSiteAt, current.LastGeoSiteLen = cfg.LastGeoSiteAt, cfg.LastGeoSiteLen
	current.LastGeoIPAt, current.LastGeoIPLen = cfg.LastGeoIPAt, cfg.LastGeoIPLen
	current.LastFetchedAt = time.Now().Unix()
	current.LastError = strings.Join(errs, "; ")
	if err := a.store.Save(geoAutoFile, current); err != nil {
		return current, err
	}
	if current.LastError != "" {
		return current, fmt.Errorf("%s", current.LastError)
	}
	return current, nil
}

// startGeoAutoLoop runs a background ticker that calls FetchGeoNow when Enabled
// and the interval has elapsed since LastFetchedAt. Stoppable via App.Shutdown.
func (a *App) startGeoAutoLoop() {
	a.geoAuto.mu.Lock()
	if a.geoAuto.running {
		a.geoAuto.mu.Unlock()
		return
	}
	a.geoAuto.running = true
	stop := make(chan struct{})
	a.geoAuto.stop = stop
	a.geoAuto.mu.Unlock()

	go func() {
		// Check once a minute so a freshly-saved config / interval edit picks up
		// within ~60s without us having to reset the ticker.
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				a.checkGeoAuto()
			}
		}
	}()
}

func (a *App) checkGeoAuto() {
	if !geoModuleAvailable() {
		return
	}
	cfg := a.GeoAuto()
	if cfg.Enabled && (cfg.LastFetchedAt == 0 ||
		time.Since(time.Unix(cfg.LastFetchedAt, 0)) >= time.Duration(cfg.IntervalHours)*time.Hour) {
		_, _ = a.FetchGeoNow()
	}
}

// stopGeoAutoLoop is called from App.Shutdown.
func (a *App) stopGeoAutoLoop() {
	a.geoAuto.mu.Lock()
	if a.geoAuto.running {
		close(a.geoAuto.stop)
		a.geoAuto.running = false
	}
	a.geoAuto.mu.Unlock()
}

func (a *App) fetchGeoFile(url, name, kind string) (int64, error) {
	c := &http.Client{Timeout: geoFetchTimeout}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "nfqws2-strategy/geo-auto")
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode == http.StatusPartialContent || resp.Header.Get("Content-Range") != "" {
		return 0, fmt.Errorf("incomplete Geo download: server returned a byte range")
	}
	file, err := a.store.StageBlob("geo", resp.Body)
	if err != nil {
		return 0, err
	}
	defer file.Discard()
	if file.Size == 0 || (resp.ContentLength > 0 && file.Size != resp.ContentLength) {
		return 0, fmt.Errorf("incomplete Geo download (%d bytes)", file.Size)
	}
	return file.Size, a.commitGeoFile(file, name, kind)
}
