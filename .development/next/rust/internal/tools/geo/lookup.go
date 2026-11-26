package geo

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// Parsed-file cache. A 10 MB geosite.dat parse takes ~1 s on a router CPU and an
// apply expands ~8 categories, so re-parsing on every lookup would dominate
// apply time. But the parsed map itself is ~100 MB (map[string][]string blows
// up the original protobuf 5-10x), so we'd also bloat the selector's RSS if we
// kept it forever.
//
// Compromise: cache entries are dropped 60 s after the last access. Apply
// finishes in seconds, so the cache stays hot through the burst of lookups and
// then frees itself. The watchdog's periodic refresh re-warms it for a moment
// every minute, which is fine.
//
// Keyed on (path, mtime, size) so a hot-swapped .dat via the Geo tab or the
// auto-fetcher is picked up on the next lookup without an explicit hook.
type cacheEntry struct {
	mtime  time.Time
	size   int64
	cats   map[string][]string
	access time.Time // last time this entry was returned to a caller; sweep deadline
}

var (
	parseCache    sync.Map // map[absPath]*cacheEntry
	sweepOnce     sync.Once
	cacheTTL      = 10 * time.Second
	cacheSweepInt = 5 * time.Second
)

func cachedParse(path, kind string) (map[string][]string, error) {
	startSweeper()
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if v, ok := parseCache.Load(path); ok {
		c := v.(*cacheEntry)
		if c.mtime.Equal(st.ModTime()) && c.size == st.Size() {
			c.access = time.Now()
			return c.cats, nil
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cats := Parse(kind, data)
	parseCache.Store(path, &cacheEntry{
		mtime:  st.ModTime(),
		size:   st.Size(),
		cats:   cats,
		access: time.Now(),
	})
	return cats, nil
}

// startSweeper kicks off the single background goroutine that drops idle cache
// entries. Safe to call from every cachedParse — sync.Once guarantees one
// goroutine for the process.
func startSweeper() {
	sweepOnce.Do(func() {
		go func() {
			t := time.NewTicker(cacheSweepInt)
			defer t.Stop()
			for range t.C {
				cutoff := time.Now().Add(-cacheTTL)
				evicted := 0
				parseCache.Range(func(k, v any) bool {
					if c, ok := v.(*cacheEntry); ok && c.access.Before(cutoff) {
						parseCache.Delete(k)
						evicted++
					}
					return true
				})
				// Go's runtime keeps the freed heap mapped to the process by
				// default — fine on a desktop, ugly on a 800 MB router where the
				// difference between selector eating 200 MB and 20 MB matters.
				// After a sweep that actually dropped something, force a GC and
				// hand the pages back to the OS so RSS tracks reality.
				if evicted > 0 {
					runtime.GC()
					debug.FreeOSMemory()
				}
			}
		}()
	})
}

// LookupCategory finds `category` (case-insensitive) across every file in geoDir
// whose kind matches the requested one (per the meta map in geoDir/geo_meta.json)
// and returns the merged, de-duplicated entry list. Empty result + nil error
// means no file of that kind contains the category; this is normal and lets the
// caller (e.g. the AWG zone parser) surface a friendlier "загрузите geosite.dat"
// message instead of an opaque "category not found".
//
// `kind` must be KindGeoSite or KindGeoIP (text-list files have no concept of
// category, so we ignore them here). Returns an error only when geo_meta.json
// itself is unreadable.
func LookupCategory(geoDir, kind, category string) ([]string, error) {
	if geoDir == "" || category == "" {
		return nil, nil
	}
	switch kind {
	case KindGeoSite, KindGeoIP:
	default:
		return nil, nil
	}

	// geo_meta.json is written by app.SaveGeoFile to the store ROOT
	// (a.store.Save(geoMetaFile)), not into the per-kind geo/ subdirectory. So
	// the meta lives one level up from the .dat files themselves.
	meta := map[string]string{}
	metaPath := filepath.Join(filepath.Dir(geoDir), "geo_meta.json")
	if b, err := os.ReadFile(metaPath); err == nil {
		_ = json.Unmarshal(b, &meta)
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	want := strings.ToLower(category)
	seen := map[string]struct{}{}
	var out []string
	for name, k := range meta {
		if k != kind {
			continue
		}
		m, err := cachedParse(filepath.Join(geoDir, name), k)
		if err != nil {
			continue
		}
		for _, e := range m[want] {
			if _, dup := seen[e]; dup {
				continue
			}
			seen[e] = struct{}{}
			out = append(out, e)
		}
	}
	return out, nil
}

// LookupAnyCategory tries both kinds (geosite, then geoip) — useful for a single
// xray-style "geosite:" or "geoip:" entry where the caller already routed by
// prefix and just wants entries.
func LookupAnyCategory(geoDir, kind, category string) ([]string, error) {
	return LookupCategory(geoDir, kind, category)
}
