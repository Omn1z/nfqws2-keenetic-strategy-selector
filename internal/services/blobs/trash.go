package blobs

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// maxTrashedBlobs caps the recycle bin so soft-deletes can't fill the router's
// limited flash. The oldest entries beyond this are pruned on each delete.
const maxTrashedBlobs = 50

func (s *Service) trashDir() string { return s.store.Path("blobs_trash") }

// sanitizeBlobName rejects empty/path-traversal names and returns the base name.
func sanitizeBlobName(name string) (string, error) {
	name = filepath.Base(name)
	if name == "" || name == "." || strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("invalid blob name")
	}
	return name, nil
}

// TrashedBlobs lists soft-deleted custom blobs, newest first.
func (s *Service) TrashedBlobs() []string {
	entries, err := os.ReadDir(s.trashDir())
	if err != nil {
		return nil
	}
	type fe struct {
		name string
		mod  int64
	}
	fs := make([]fe, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		fs = append(fs, fe{e.Name(), info.ModTime().UnixNano()})
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].mod > fs[j].mod })
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.name
	}
	return out
}

// trashBlob moves a custom blob into the trash (a same-named trashed entry is
// overwritten — the most recent deletion wins) and prunes the oldest over cap.
func (s *Service) trashBlob(name string) error {
	if err := os.MkdirAll(s.trashDir(), 0o755); err != nil {
		return err
	}
	if err := s.store.Move(filepath.Join("blobs", name), filepath.Join("blobs_trash", name)); err != nil {
		return err
	}
	names := s.TrashedBlobs() // newest first
	for i := maxTrashedBlobs; i < len(names); i++ {
		_ = os.Remove(filepath.Join(s.trashDir(), names[i]))
	}
	return nil
}

// RestoreBlob moves a trashed blob back to the active set. It refuses if an
// active blob already has that name, so a live blob is never clobbered.
func (s *Service) RestoreBlob(name string) error {
	name, err := sanitizeBlobName(name)
	if err != nil {
		return err
	}
	if s.store.Exists(filepath.Join("blobs", name)) {
		return fmt.Errorf("активный блоб «%s» уже существует — удалите или переименуйте его", name)
	}
	return s.store.Move(filepath.Join("blobs_trash", name), filepath.Join("blobs", name))
}

// PurgeBlob permanently removes a single trashed blob (user-initiated).
func (s *Service) PurgeBlob(name string) error {
	name, err := sanitizeBlobName(name)
	if err != nil {
		return err
	}
	return s.store.Delete(filepath.Join("blobs_trash", name))
}

// EmptyTrash permanently removes all trashed blobs (user-initiated).
func (s *Service) EmptyTrash() error {
	for _, n := range s.TrashedBlobs() {
		if err := s.store.Delete(filepath.Join("blobs_trash", n)); err != nil {
			return err
		}
	}
	return nil
}
