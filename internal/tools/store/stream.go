package store

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// StagedBlob is a closed, synced file on the destination filesystem. It is
// excluded from backups until MoveTo publishes it. Call Discard on every path.
type StagedBlob struct {
	store *Store
	rel   string
	Size  int64
}

func (s *Store) StageBlob(dir string, src io.Reader) (*StagedBlob, error) {
	staging := filepath.Join(dir, ".store")
	if err := mkdirDurable(s.Path(dir), 0755); err != nil {
		return nil, err
	}
	if err := mkdirDurable(s.Path(staging), 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(s.Path(staging))
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("invalid blob staging directory")
	}
	f, err := os.CreateTemp(s.Path(staging), "upload-*")
	if err != nil {
		return nil, err
	}
	staged := &StagedBlob{store: s, rel: filepath.Join(staging, filepath.Base(f.Name()))}
	// In particular do not hold the store mutex or file lock while reading a WAN response.
	staged.Size, err = io.Copy(f, src)
	if err == nil {
		err = f.Chmod(0644)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		staged.Discard()
		return nil, err
	}
	return staged, nil
}

func (b *StagedBlob) MoveTo(rel string) error { return b.store.Move(b.rel, rel) }

func (b *StagedBlob) Discard() { _ = os.Remove(b.store.Path(b.rel)) }
