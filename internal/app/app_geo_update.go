package app

import (
	"fmt"
	"io"
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
	return a.store.Save(geoAutoFile, cfg)
}

// FetchGeoNow runs one synchronous fetch cycle and updates the persisted status.
// Errors from individual downloads are recorded in LastError but never block the
// other kind (geosite failure does not skip geoip and vice versa).
func (a *App) FetchGeoNow() (*GeoAutoConfig, error) {
	cfg := a.GeoAuto()
	a.geoAuto.mu.Lock()
	since := time.Since(a.geoAuto.last)
	a.geoAuto.mu.Unlock()
	if since > 0 && since < geoFetchMinInterval {
		return cfg, fmt.Errorf("слишком часто: подождите %s между запросами", geoFetchMinInterval-since)
	}
	a.geoAuto.mu.Lock()
	a.geoAuto.last = time.Now()
	a.geoAuto.mu.Unlock()

	var errs []string
	if u := strings.TrimSpace(cfg.GeoSiteURL); u != "" {
		if data, err := httpGet(u); err != nil {
			errs = append(errs, "geosite: "+err.Error())
		} else if err := a.SaveGeoFile("geosite.dat", geo.KindGeoSite, data); err != nil {
			errs = append(errs, "geosite save: "+err.Error())
		} else {
			cfg.LastGeoSiteAt = time.Now().Unix()
			cfg.LastGeoSiteLen = int64(len(data))
		}
	}
	if u := strings.TrimSpace(cfg.GeoIPURL); u != "" {
		if data, err := httpGet(u); err != nil {
			errs = append(errs, "geoip: "+err.Error())
		} else if err := a.SaveGeoFile("geoip.dat", geo.KindGeoIP, data); err != nil {
			errs = append(errs, "geoip save: "+err.Error())
		} else {
			cfg.LastGeoIPAt = time.Now().Unix()
			cfg.LastGeoIPLen = int64(len(data))
		}
	}
	cfg.LastFetchedAt = time.Now().Unix()
	cfg.LastError = strings.Join(errs, "; ")
	_ = a.store.Save(geoAutoFile, cfg)
	if len(errs) > 0 {
		return cfg, fmt.Errorf("%s", cfg.LastError)
	}
	return cfg, nil
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
	a.geoAuto.stop = make(chan struct{})
	a.geoAuto.mu.Unlock()

	go func() {
		// Check once a minute so a freshly-saved config / interval edit picks up
		// within ~60s without us having to reset the ticker.
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-a.geoAuto.stop:
				return
			case <-t.C:
				cfg := a.GeoAuto()
				if !cfg.Enabled {
					continue
				}
				due := cfg.LastFetchedAt == 0 ||
					time.Since(time.Unix(cfg.LastFetchedAt, 0)) >= time.Duration(cfg.IntervalHours)*time.Hour
				if !due {
					continue
				}
				if _, err := a.FetchGeoNow(); err != nil {
					// Already recorded in LastError; no need to log spam.
					_ = err
				}
			}
		}
	}()
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

func httpGet(url string) ([]byte, error) {
	c := &http.Client{Timeout: geoFetchTimeout}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nfqws2-strategy/geo-auto")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}
