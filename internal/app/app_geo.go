package app

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"os"
	"path/filepath"
	"strings"

	"nfqws2strategy/internal/tools/geo"
	"nfqws2strategy/internal/tools/store"
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
	a.geoFilesMu.Lock()
	defer a.geoFilesMu.Unlock()
	m, _ := a.readGeoMeta()
	return m
}

func (a *App) readGeoMeta() (map[string]string, error) {
	m := map[string]string{}
	if err := a.store.Load(geoMetaFile, &m); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if m == nil {
		return nil, fmt.Errorf("invalid geo metadata")
	}
	return m, nil
}

func validGeoName(name string) bool {
	return filepath.IsLocal(name) && name != "." && !strings.EqualFold(name, ".store") && name == filepath.Base(name) &&
		!strings.ContainsAny(name, "/\\:\x00")
}

// SaveGeoFile stores an uploaded geo file with its kind.
func (a *App) SaveGeoFile(name, kind string, data []byte) error {
	_, err := a.saveGeoStream(name, kind, bytes.NewReader(data))
	return err
}

func (a *App) saveGeoStream(name, kind string, src io.Reader) (int64, error) {
	if !validGeoName(name) {
		return 0, fmt.Errorf("invalid file name")
	}
	file, err := a.store.StageBlob("geo", src)
	if err != nil {
		return 0, err
	}
	defer file.Discard()
	return file.Size, a.commitGeoFile(file, name, kind)
}

func (a *App) commitGeoFile(file *store.StagedBlob, name, kind string) error {
	a.geoFilesMu.Lock()
	defer a.geoFilesMu.Unlock()
	m, err := a.readGeoMeta()
	if err != nil {
		return err
	}
	oldKind, existed := m[name]
	kind = geoKind(kind)
	changed := !existed || oldKind != kind
	if changed {
		m[name] = kind
		if err := a.store.Save(geoMetaFile, m); err != nil {
			return err
		}
	}
	err = file.MoveTo(filepath.Join("geo", name))
	var committed *store.CommitError
	if err != nil && changed && !errors.As(err, &committed) {
		if existed {
			m[name] = oldKind
		} else {
			delete(m, name)
		}
		return errors.Join(err, a.store.Save(geoMetaFile, m))
	}
	return err
}

// SaveGeoUpload streams the multipart file directly to its final filesystem.
// The browser sends kind after file. Commit after the terminating boundary so
// an interrupted request cannot publish even a fully received first part.
func (a *App) SaveGeoUpload(form *multipart.Reader, defaultKind string) (name, kind string, err error) {
	var file *store.StagedBlob
	kind = defaultKind
	hasKind := defaultKind != ""
	for {
		part, err := form.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", err
		}
		switch part.FormName() {
		case "file":
			if file != nil {
				continue
			}
			name = part.FileName()
			if !validGeoName(name) {
				return "", "", fmt.Errorf("invalid file name")
			}
			file, err = a.store.StageBlob("geo", part)
			if err != nil {
				return "", "", err
			}
			defer file.Discard()
		case "kind":
			if hasKind || part.FileName() != "" {
				continue
			}
			const maxKind = 64
			b, err := io.ReadAll(io.LimitReader(part, maxKind+1))
			if err != nil || len(b) > maxKind {
				return "", "", fmt.Errorf("invalid geo kind field")
			}
			kind = string(b)
			hasKind = true
		}
	}
	if file == nil {
		return "", "", fmt.Errorf("missing file")
	}
	return name, kind, a.commitGeoFile(file, name, kind)
}

func (a *App) DeleteGeoFile(name string) error {
	if !validGeoName(name) {
		return fmt.Errorf("invalid file name")
	}
	a.geoFilesMu.Lock()
	defer a.geoFilesMu.Unlock()
	m, err := a.readGeoMeta()
	if err != nil {
		return err
	}
	if err := a.store.Delete(filepath.Join("geo", name)); err != nil {
		return err
	}
	delete(m, name)
	return a.store.Save(geoMetaFile, m)
}

func geoKind(kind string) string {
	switch kind {
	case geo.KindGeoSite, geo.KindGeoIP:
		return kind
	default:
		return geo.KindText
	}
}

// GeoFiles lists uploaded geo files with their categories (parsed on demand).
func (a *App) GeoFiles() []GeoFileInfo {
	meta := a.geoMeta()
	available := geoModuleAvailable()
	out := []GeoFileInfo{}
	for name, kind := range meta {
		info := GeoFileInfo{Name: name, Kind: kind}
		if available && validGeoName(name) {
			info.Categories, _ = listGeoCategories(filepath.Join(a.geoDir(), name), geoKind(kind))
		}
		out = append(out, info)
	}
	return out
}

// ImportGeo appends a category's entries (capped at limit, 0 = all) into a list,
// creating it when listID is empty. Entries that parse as IP/CIDR go to IPs, the
// rest to domains.
func (a *App) ImportGeo(geoName, category string, limit int, listID, listName string) (*List, error) {
	items, err := a.ResolveGeo(geoName, category, limit)
	if err != nil {
		return nil, err
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
	if !validGeoName(geoName) {
		return nil, fmt.Errorf("invalid file name")
	}
	return extractGeoCategory(filepath.Join(a.geoDir(), geoName), geoKind(a.geoMeta()[geoName]), category, limit)
}

func isIPish(s string) bool {
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return net.ParseIP(s) != nil
}
