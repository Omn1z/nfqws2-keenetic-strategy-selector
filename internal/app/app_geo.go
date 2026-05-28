package app

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"nfqws2strategy/internal/geo"
)

const geoMetaFile = "geo_meta.json"

// GeoFileInfo describes an uploaded geo file and its categories.
type GeoFileInfo struct {
	Name       string         `json:"name"`
	Kind       string         `json:"kind"`
	Categories []geo.Category `json:"categories"`
}

func (a *App) geoDir() string { return a.store.Path("geo") }

func (a *App) geoMeta() map[string]string {
	m := map[string]string{}
	_ = a.store.Load(geoMetaFile, &m)
	return m
}

// SaveGeoFile stores an uploaded geo file with its kind.
func (a *App) SaveGeoFile(name, kind string, data []byte) error {
	name = filepath.Base(name)
	if name == "" || name == "." || strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("invalid file name")
	}
	switch kind {
	case geo.KindGeoSite, geo.KindGeoIP, geo.KindText:
	default:
		kind = geo.KindText
	}
	if err := a.store.WriteBytes(filepath.Join("geo", name), data); err != nil {
		return err
	}
	m := a.geoMeta()
	m[name] = kind
	return a.store.Save(geoMetaFile, m)
}

func (a *App) DeleteGeoFile(name string) error {
	name = filepath.Base(name)
	_ = a.store.Delete(filepath.Join("geo", name))
	m := a.geoMeta()
	delete(m, name)
	return a.store.Save(geoMetaFile, m)
}

func (a *App) parseGeo(name string) (string, map[string][]string, error) {
	name = filepath.Base(name)
	kind := a.geoMeta()[name]
	if kind == "" {
		kind = geo.KindText
	}
	data, err := os.ReadFile(filepath.Join(a.geoDir(), name))
	if err != nil {
		return kind, nil, err
	}
	return kind, geo.Parse(kind, data), nil
}

// GeoFiles lists uploaded geo files with their categories (parsed on demand).
func (a *App) GeoFiles() []GeoFileInfo {
	meta := a.geoMeta()
	out := []GeoFileInfo{}
	for name, kind := range meta {
		info := GeoFileInfo{Name: name, Kind: kind}
		if _, m, err := a.parseGeo(name); err == nil {
			info.Categories = geo.Categories(m)
		}
		out = append(out, info)
	}
	return out
}

// ImportGeo appends a category's entries (capped at limit, 0 = all) into a list,
// creating it when listID is empty. Entries that parse as IP/CIDR go to IPs, the
// rest to domains.
func (a *App) ImportGeo(geoName, category string, limit int, listID, listName string) (*List, error) {
	_, m, err := a.parseGeo(geoName)
	if err != nil {
		return nil, err
	}
	items, ok := m[strings.ToLower(category)]
	if !ok {
		return nil, fmt.Errorf("category %q not found", category)
	}
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}

	var list *List
	if listID != "" {
		list, err = a.GetList(listID)
		if err != nil {
			return nil, fmt.Errorf("list not found")
		}
	} else {
		if listName == "" {
			listName = geoName + ":" + category
		}
		list = &List{Name: listName}
	}
	for _, it := range items {
		if isIPish(it) {
			list.IPs = append(list.IPs, it)
		} else {
			list.Domains = append(list.Domains, it)
		}
	}
	return a.SaveList(list)
}

// ResolveGeo returns a category's entries (capped at limit, 0 = all) as a flat
// target list, without creating a list — used for ad-hoc runs/checks against a
// geo category.
func (a *App) ResolveGeo(geoName, category string, limit int) ([]string, error) {
	_, m, err := a.parseGeo(geoName)
	if err != nil {
		return nil, err
	}
	items, ok := m[strings.ToLower(category)]
	if !ok {
		return nil, fmt.Errorf("category %q not found", category)
	}
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	return append([]string{}, items...), nil
}

func isIPish(s string) bool {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return net.ParseIP(s) != nil
}
