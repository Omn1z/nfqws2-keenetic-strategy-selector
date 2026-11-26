//go:build linux

package openwrtdns

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTransactionLockCoordinatesManagersAndCancellation(t *testing.T) {
	filename := filepath.Join(t.TempDir(), snapshotName)
	unlock, err := lockTransaction(context.Background(), filename)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if second, err := lockTransaction(ctx, filename); !errors.Is(err, context.DeadlineExceeded) {
		if second != nil {
			second()
		}
		t.Fatalf("second lock=%v", err)
	}
	unlock()
	again, err := lockTransaction(context.Background(), filename)
	if err != nil {
		t.Fatal(err)
	}
	again()
	if _, err = os.Stat(filename + ".lock"); err != nil {
		t.Fatal("lock inode must survive unlock", err)
	}
}
func TestTransactionLockRejectsSymlinks(t *testing.T) {
	filename := filepath.Join(t.TempDir(), snapshotName)
	target := filepath.Join(t.TempDir(), "foreign")
	if err := os.WriteFile(target, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filename+".lock"); err != nil {
		t.Fatal(err)
	}
	if unlock, err := lockTransaction(context.Background(), filename); err == nil {
		unlock()
		t.Fatal("followed symlink lock")
	}
}
func TestSnapshotPermissions(t *testing.T) {
	m, _ := newFixture(t)
	applyFixture(t, m)
	info, err := os.Stat(m.filename)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("snapshot mode %v", info.Mode())
	}
}
