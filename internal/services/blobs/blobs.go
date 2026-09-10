// Package blobs owns the fake-payload blob store behind the Blobs tab: listing
// system + custom blobs, resolving a blob name to its nfqws2 --blob identifier and
// on-disk path, saving / soft-deleting custom uploads, the recycle bin, and
// capturing / validating / generating TLS ClientHello payloads. Custom blobs live
// in the on-disk store under <data>/blobs (+ blobs_trash); read-only system blobs
// live in cfg.SystemBlobsDir.
package blobs

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"nfqws2strategy/internal/tools/config"
	"nfqws2strategy/internal/tools/store"
)

// Service owns the blob store plus the in-memory ClientHello-capture registry.
type Service struct {
	cfg   *config.Config
	store *store.Store

	capMu    sync.Mutex
	caps     map[string]*BlobCapture
	capOrder []string
}

// New ensures the custom-blob directory exists and returns the service.
func New(cfg *config.Config, st *store.Store) (*Service, error) {
	s := &Service{cfg: cfg, store: st, caps: map[string]*BlobCapture{}}
	if err := os.MkdirAll(s.Dir(), 0o755); err != nil {
		return nil, err
	}
	return s, nil
}

// Dir is the custom-blob directory under the data dir.
func (s *Service) Dir() string { return s.store.Path("blobs") }

// Blobs lists available blob names: system blobs plus user-uploaded ones.
func (s *Service) Blobs() (system []string, custom []string) {
	if entries, err := os.ReadDir(s.cfg.SystemBlobsDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				system = append(system, e.Name())
			}
		}
	}
	if names, err := s.store.ListFiles("blobs"); err == nil {
		custom = names
	}
	sort.Strings(system)
	sort.Strings(custom)
	return
}

// ResolveBlob maps a selected blob filename to its lua name and absolute path,
// preferring a custom upload over a system blob of the same name. The lua name is
// the filename without extension.
func (s *Service) ResolveBlob(name string) (luaName, path string, ok bool) {
	name = filepath.Base(name)
	if name == "" || name == "." {
		return "", "", false
	}
	path = filepath.Join(s.Dir(), name)
	if _, err := os.Stat(path); err != nil {
		path = filepath.Join(s.cfg.SystemBlobsDir, name)
		if _, err := os.Stat(path); err != nil {
			return "", "", false
		}
	}
	return luaIdent(strings.TrimSuffix(name, filepath.Ext(name))), path, true
}

// reNonIdent matches characters not allowed in an nfqws2 blob (Lua) identifier.
var reNonIdent = regexp.MustCompile(`[^A-Za-z0-9_]`)

// luaIdent turns a blob filename stem into a valid nfqws2 --blob=NAME identifier.
// Captured/generated blobs are named after the SNI (e.g. clienthello_edge.microsoft.com),
// and nfqws2 rejects dots/dashes as a "bad identifier", so they're folded to '_'.
func luaIdent(s string) string {
	s = reNonIdent.ReplaceAllString(s, "_")
	if s == "" || (s[0] >= '0' && s[0] <= '9') {
		s = "b_" + s
	}
	return s
}

// SaveBlob stores an uploaded blob and returns the absolute path to reference it
// in a strategy via --blob=name:@<path>.
func (s *Service) SaveBlob(name string, data []byte) (string, error) {
	name, err := sanitizeBlobName(name)
	if err != nil {
		return "", err
	}
	if err := s.store.WriteBytes(filepath.Join("blobs", name), data); err != nil {
		return "", err
	}
	return filepath.Join(s.Dir(), name), nil
}

// DeleteBlob soft-deletes a custom (user-uploaded) blob by moving it to the
// recycle bin (TrashedBlobs / RestoreBlob / PurgeBlob). System blobs live outside
// the data dir and are never touched.
func (s *Service) DeleteBlob(name string) error {
	name, err := sanitizeBlobName(name)
	if err != nil {
		return err
	}
	return s.trashBlob(name)
}
