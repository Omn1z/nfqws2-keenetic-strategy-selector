// Package store is a tiny JSON file store with atomic writes, sized for the
// router's limited flash. It is safe for concurrent use.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

type Store struct {
	dir     string
	mu      sync.Mutex
	configs map[string]*configState
	fault   func(stage, path string) error // fault injection; nil outside tests
}

func New(dir string) (*Store, error) {
	if err := mkdirDurable(dir, 0o755); err != nil {
		return nil, err
	}
	return &Store{dir: dir, configs: make(map[string]*configState)}, nil
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
	return s.withExclusiveLocked(func() error { return s.saveLocked(rel, v, 0o644, false) })
}

// SaveSecret marshals v as indented JSON and writes it atomically with 0600
// permissions (for files holding credentials / private keys, e.g. awg.json).
func (s *Store) SaveSecret(rel string, v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.withExclusiveLocked(func() error { return s.saveLocked(rel, v, 0o600, false) })
}

func (s *Store) saveLocked(rel string, v any, mode os.FileMode, force bool) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return s.writeLocked(rel, b, mode, force)
}

// Load reads JSON into v. Returns os.ErrNotExist if missing.
func (s *Store) Load(rel string, v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(filepath.Join(s.dir, rel))
	if err != nil {
		return err
	}
	return decodeIsolated(b, v, true)
}

func (s *Store) Exists(rel string) bool {
	_, err := os.Stat(filepath.Join(s.dir, rel))
	return err == nil
}

func (s *Store) Delete(rel string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.withExclusiveLocked(func() error {
		// Invalidate recovery before removing the primary, so an interrupted
		// intentional delete cannot resurrect it from a surviving backup.
		for _, name := range s.snapshotPaths(rel) {
			if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		if err := syncDirectory(s.metadataDir()); err != nil {
			return err
		}
		err := os.Remove(s.Path(rel))
		if os.IsNotExist(err) {
			err = nil
		}
		if err == nil {
			err = syncDirectory(filepath.Dir(s.Path(rel)))
		}
		if err == nil {
			if c := s.configs[rel]; c != nil {
				c.exists, c.blocked = false, nil
			}
		}
		return err
	})
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
	return s.withExclusiveLocked(func() error {
		if s.configs[srcRel] != nil || s.configs[dstRel] != nil {
			return fmt.Errorf("move: protected configurations require explicit restore")
		}
		dst, src := s.Path(dstRel), s.Path(srcRel)
		if err := mkdirDurable(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := os.Rename(src, dst); err != nil {
			return err
		}
		if err := syncDirectory(filepath.Dir(dst)); err != nil {
			return err
		}
		if filepath.Dir(src) != filepath.Dir(dst) {
			return syncDirectory(filepath.Dir(src))
		}
		return nil
	})
}

// WriteBytes writes raw bytes atomically (used for uploaded blobs).
func (s *Store) WriteBytes(rel string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.withExclusiveLocked(func() error { return s.writeLocked(rel, data, 0o644, false) })
}

// WithExclusive fences raw archive restoration against all Store writers,
// including another panel/CLI process. fn must not call Store methods.
func (s *Store) WithExclusive(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.withExclusiveLocked(fn)
}

func (s *Store) withExclusiveLocked(fn func() error) error {
	if err := s.ensureMetadata(); err != nil {
		return err
	}
	unlock, err := lockStoreFile(filepath.Join(s.metadataDir(), "lock"))
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

// CommitError means rename completed but its durability could not be confirmed.
// Callers must not assume that the old file is still on disk.
type CommitError struct{ Err error }

func (e *CommitError) Error() string {
	return "configuration replacement needs verification: " + e.Err.Error()
}
func (e *CommitError) Unwrap() error { return e.Err }

func (s *Store) checkpoint(stage, path string) error {
	if s.fault != nil {
		return s.fault(stage, path)
	}
	return nil
}

func (s *Store) durableReplace(full string, b []byte, mode os.FileMode) (committed bool, err error) {
	dir := filepath.Dir(full)
	if err = mkdirDurable(dir, 0o755); err != nil {
		return false, err
	}
	f, err := os.CreateTemp(dir, ".n2s-write-*")
	if err != nil {
		return false, err
	}
	name := f.Name()
	defer func() { _ = f.Close(); _ = os.Remove(name) }()
	// Chmod the private newly-created inode before it can become the target.
	if err = f.Chmod(mode); err != nil {
		return false, err
	}
	if err = s.checkpoint("write", full); err == nil {
		_, err = f.Write(b)
	}
	if err != nil {
		return false, err
	}
	if err = s.checkpoint("file-sync", full); err == nil {
		err = f.Sync()
	}
	if err != nil {
		return false, err
	}
	if err = s.checkpoint("close", full); err != nil {
		return false, err
	}
	if err = f.Close(); err != nil {
		return false, err
	}
	if err = s.checkpoint("rename", full); err == nil {
		err = os.Rename(name, full)
	}
	if err != nil {
		return false, err
	}
	if err = s.checkpoint("dir-sync", full); err == nil {
		err = syncDirectory(dir)
	}
	if err != nil {
		return true, &CommitError{Err: err}
	}
	return true, nil
}

var (
	ErrConfigUnavailable = errors.New("saved configuration is unavailable; restore a backup or explicitly reset it")
	ErrConfigChanged     = errors.New("configuration changed on disk; reload before saving")
)

func mkdirDurable(dir string, mode os.FileMode) error {
	var missing []string
	for p := filepath.Clean(dir); ; p = filepath.Dir(p) {
		_, err := os.Stat(p)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) {
			return err
		}
		missing = append(missing, p)
		if filepath.Dir(p) == p {
			break
		}
	}
	if err := os.MkdirAll(dir, mode); err != nil {
		return err
	}
	for i := len(missing) - 1; i >= 0; i-- {
		if err := syncDirectory(filepath.Dir(missing[i])); err != nil {
			return err
		}
	}
	return nil
}
