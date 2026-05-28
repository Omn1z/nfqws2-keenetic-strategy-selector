// Package store is a tiny JSON file store with atomic writes, sized for the
// router's limited flash. It is safe for concurrent use.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

type Store struct {
	dir string
	mu  sync.Mutex
}

func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// NewID returns a short random hex id.
func NewID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Store) Path(rel string) string { return filepath.Join(s.dir, rel) }

// Save marshals v as indented JSON and writes it atomically (temp + rename).
func (s *Store) Save(rel string, v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(rel, v)
}

func (s *Store) saveLocked(rel string, v any) error {
	full := filepath.Join(s.dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := full + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, full)
}

// Load reads JSON into v. Returns os.ErrNotExist if missing.
func (s *Store) Load(rel string, v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(filepath.Join(s.dir, rel))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func (s *Store) Exists(rel string) bool {
	_, err := os.Stat(filepath.Join(s.dir, rel))
	return err == nil
}

func (s *Store) Delete(rel string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(filepath.Join(s.dir, rel))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// ListFiles returns the base filenames in subdir (non-recursive), sorted.
func (s *Store) ListFiles(subdir string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, subdir))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// Move renames a file within the store (used to move a blob to/from the trash).
// The destination directory is created; an existing destination is overwritten.
func (s *Store) Move(srcRel, dstRel string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dst := filepath.Join(s.dir, dstRel)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.Rename(filepath.Join(s.dir, srcRel), dst)
}

// WriteBytes writes raw bytes atomically (used for uploaded blobs).
func (s *Store) WriteBytes(rel string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	full := filepath.Join(s.dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	tmp := full + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, full)
}
