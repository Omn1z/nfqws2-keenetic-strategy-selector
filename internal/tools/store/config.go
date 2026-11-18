package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
)

type configState struct {
	validate func([]byte) error
	hash     [32]byte
	exists   bool
	blocked  error
}

type configSnapshot struct {
	Version    int    `json:"version"`
	Generation uint64 `json:"generation"`
	Data       []byte `json:"data"`
	Checksum   string `json:"sha256"`
	slot       int
}

func (s *Store) metadataDir() string { return filepath.Join(s.dir, ".store") }
func (s *Store) ensureMetadata() error {
	dir := s.metadataDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("invalid configuration recovery directory")
	}
	if st.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	return syncDirectory(s.dir)
}
func (s *Store) snapshotPrefix(rel string) string {
	hash := sha256.Sum256([]byte(filepath.Clean(rel)))
	return filepath.Join(s.metadataDir(), hex.EncodeToString(hash[:]))
}
func (s *Store) snapshotPaths(rel string) []string {
	prefix := s.snapshotPrefix(rel)
	return []string{prefix + ".0.json", prefix + ".1.json"}
}
func snapshotChecksum(v configSnapshot) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d:%d:", v.Version, v.Generation)
	_, _ = h.Write(v.Data)
	return hex.EncodeToString(h.Sum(nil))
}
func validateConfig(data []byte, validator func([]byte) error) error {
	if !json.Valid(data) || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return fmt.Errorf("invalid or empty configuration JSON")
	}
	if validator != nil {
		return validator(data)
	}
	return nil
}
func (s *Store) snapshots(rel string, validator func([]byte) error) (out []configSnapshot, found bool) {
	for slot, name := range s.snapshotPaths(rel) {
		data, err := os.ReadFile(name)
		if os.IsNotExist(err) {
			continue
		}
		found = true
		if err != nil {
			continue
		}
		var snap configSnapshot
		if json.Unmarshal(data, &snap) != nil || snap.Version != 1 || snap.Generation == 0 || snap.Checksum != snapshotChecksum(snap) || validateConfig(snap.Data, validator) != nil {
			continue
		}
		snap.slot = slot
		out = append(out, snap)
	}
	return out, found
}
func (s *Store) snapshot(rel string, data []byte, validator func([]byte) error) error {
	if err := validateConfig(data, validator); err != nil {
		return err
	}
	snaps, _ := s.snapshots(rel, validator)
	var last *configSnapshot
	for i := range snaps {
		if last == nil || snaps[i].Generation > last.Generation {
			last = &snaps[i]
		}
	}
	if last != nil && bytes.Equal(last.Data, data) {
		return nil
	}
	seq, slot := uint64(1), 0
	if last != nil {
		seq = last.Generation + 1
		slot = 1 - last.slot
	}
	if seq == 0 {
		return fmt.Errorf("configuration recovery generation overflow")
	}
	snap := configSnapshot{Version: 1, Generation: seq, Data: data}
	snap.Checksum = snapshotChecksum(snap)
	b, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	_, err = s.durableReplace(s.snapshotPaths(rel)[slot], b, 0o600)
	return err
}

// LoadConfig registers a critical JSON document, validates candidates before
// publishing them and recovers a damaged/missing primary from two checksummed
// generations. Unrecoverable documents are never replaced by an ordinary save.
func (s *Store) LoadConfig(rel string, v any, validator func([]byte) error) (recovered bool, result error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.configs == nil {
		s.configs = map[string]*configState{}
	}
	state := &configState{validate: validator}
	s.configs[rel] = state
	ran := false
	result = s.withExclusiveLocked(func() error {
		ran = true
		data, readErr := os.ReadFile(s.Path(rel))
		if readErr == nil && validateConfig(data, validator) == nil {
			if err := decodeIsolated(data, v, true); err == nil {
				state.hash, state.exists = sha256.Sum256(data), true
				if err := s.snapshot(rel, data, validator); err != nil {
					log.Printf("store: recovery copy unavailable for %s: %v", rel, err)
				}
				return nil
			}
		}
		// I/O/permission errors are not proof of corruption. Preserve the file.
		if readErr != nil && !os.IsNotExist(readErr) {
			return fmt.Errorf("%w: %s could not be read", ErrConfigUnavailable, rel)
		}
		snaps, found := s.snapshots(rel, validator)
		for len(snaps) > 0 {
			latest := 0
			for i := range snaps {
				if snaps[i].Generation > snaps[latest].Generation {
					latest = i
				}
			}
			candidate := snaps[latest]
			snaps = append(snaps[:latest], snaps[latest+1:]...)
			if err := decodeIsolated(candidate.Data, v, false); err != nil {
				continue
			}
			if readErr == nil {
				// Preserve evidence durably before replacing damaged credentials.
				if _, err := s.durableReplace(s.snapshotPrefix(rel)+".corrupt", data, 0o600); err != nil {
					return fmt.Errorf("%w: could not preserve damaged %s", ErrConfigUnavailable, rel)
				}
			}
			if _, err := s.durableReplace(s.Path(rel), candidate.Data, 0o600); err != nil {
				return fmt.Errorf("%w: could not restore %s", ErrConfigUnavailable, rel)
			}
			if err := decodeIsolated(candidate.Data, v, true); err != nil {
				return err
			}
			state.hash, state.exists = sha256.Sum256(candidate.Data), true
			recovered = true
			log.Printf("store: restored %s from a verified recovery copy", rel)
			return nil
		}
		if os.IsNotExist(readErr) && !found {
			return os.ErrNotExist
		}
		return fmt.Errorf("%w: %s and its recovery copies are invalid", ErrConfigUnavailable, rel)
	})
	if result != nil && !ran {
		// A read-only/full filesystem must not hide an otherwise valid primary.
		if data, err := os.ReadFile(s.Path(rel)); err == nil && validateConfig(data, validator) == nil {
			if err := decodeIsolated(data, v, true); err == nil {
				state.hash, state.exists = sha256.Sum256(data), true
				log.Printf("store: loaded %s without writable recovery metadata: %v", rel, result)
				return false, nil
			}
		}
	}
	if result != nil && !os.IsNotExist(result) {
		state.blocked = result
	}
	return recovered, result
}

// RecoverConfig is reserved for an explicit validated reset/import. It bypasses
// a load-error/CAS guard, preserves damaged bytes and establishes a new baseline.
func (s *Store) RecoverConfig(rel string, v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.configs[rel] == nil {
		return fmt.Errorf("configuration must be loaded before explicit recovery")
	}
	return s.withExclusiveLocked(func() error { return s.saveLocked(rel, v, 0o600, true) })
}

func (s *Store) writeLocked(rel string, data []byte, mode os.FileMode, force bool) error {
	state := s.configs[rel]
	old, readErr := os.ReadFile(s.Path(rel))
	if state != nil {
		if err := validateConfig(data, state.validate); err != nil {
			return err
		}
		if !force {
			if state.blocked != nil {
				return fmt.Errorf("%w: %s", ErrConfigUnavailable, rel)
			}
			if readErr != nil && !os.IsNotExist(readErr) {
				return readErr
			}
			if state.exists != (readErr == nil) || (state.exists && state.hash != sha256.Sum256(old)) {
				return fmt.Errorf("%w: %s", ErrConfigChanged, rel)
			}
		}
		if readErr == nil {
			if err := validateConfig(old, state.validate); err == nil {
				// Previous committed bytes are durable before touching the primary.
				if err = s.snapshot(rel, old, state.validate); err != nil {
					return err
				}
			} else if force {
				if _, err = s.durableReplace(s.snapshotPrefix(rel)+".corrupt", old, 0o600); err != nil {
					return err
				}
			} else {
				return fmt.Errorf("%w: %s", ErrConfigUnavailable, rel)
			}
		} else if !os.IsNotExist(readErr) {
			return readErr
		}
	}
	if readErr == nil && bytes.Equal(old, data) {
		// Existing secret files may come from an older permissive build.
		if mode == 0o600 {
			if st, err := os.Stat(s.Path(rel)); err != nil {
				return err
			} else if st.Mode().Perm() != mode {
				if err := os.Chmod(s.Path(rel), mode); err != nil {
					return err
				}
				f, err := os.OpenFile(s.Path(rel), os.O_RDWR, 0)
				if err != nil {
					return err
				}
				syncErr, closeErr := f.Sync(), f.Close()
				if syncErr != nil {
					return syncErr
				}
				if closeErr != nil {
					return closeErr
				}
			}
		}
		if state != nil {
			state.exists, state.hash, state.blocked = true, sha256.Sum256(data), nil
		}
		return nil
	}
	committed, err := s.durableReplace(s.Path(rel), data, mode)
	if state != nil && committed {
		state.exists, state.hash = true, sha256.Sum256(data)
	}
	if err != nil {
		if state != nil && committed {
			// RAM may still contain the caller's old candidate. Do not permit
			// a follow-up toggle/save to replace the document that reached disk.
			// Only a validated reload or explicit recovery clears this fence.
			state.blocked = err
		}
		return err
	}
	if state != nil {
		state.blocked = nil
		// The primary is already file+directory-synced. Failure of this extra
		// current-generation mirror does not undo its durable commit; the
		// previous validated snapshot remains available.
		if err := s.snapshot(rel, data, state.validate); err != nil {
			log.Printf("store: current recovery copy unavailable for %s: %v", rel, err)
		}
	}
	return nil
}

// Decode a fresh clone of the caller's initial defaults; a bad candidate must
// never partially mutate maps/slices that a later recovery candidate inherits.
func decodeIsolated(data []byte, v any, publish bool) error {
	dst := reflect.ValueOf(v)
	if dst.Kind() != reflect.Pointer || dst.IsNil() {
		return fmt.Errorf("store: target must be a non-nil pointer")
	}
	next := reflect.New(dst.Elem().Type())
	seed, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(seed, next.Interface()); err != nil {
		return err
	}
	if err = json.Unmarshal(data, next.Interface()); err != nil {
		return err
	}
	if publish {
		dst.Elem().Set(next.Elem())
	}
	return nil
}
