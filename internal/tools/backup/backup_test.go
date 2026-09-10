package backup

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestRoundTripAndIntegrity exercises every load-bearing path: build → restore
// (roundtrip), restore of a byte-flipped archive (ErrCorrupt — MD5 catches it),
// restore of a non-selector blob (ErrNotBackup), and the allowlist guard that
// keeps a tampered archive from writing outside permitted roots. One test,
// no fixtures.
func TestRoundTripAndIntegrity(t *testing.T) {
	src := t.TempDir()
	_ = os.MkdirAll(filepath.Join(src, "sub"), 0o755)
	_ = os.WriteFile(filepath.Join(src, "a.json"), []byte("a"), 0o644)
	_ = os.WriteFile(filepath.Join(src, "sub/b.json"), []byte("b"), 0o644)

	var buf bytes.Buffer
	if n, err := Build([]string{src}, &buf); err != nil || n != 2 {
		t.Fatalf("Build n=%d err=%v", n, err)
	}

	// Backups encode absolute paths; restoring "under src" means dst==src, and
	// the files land exactly where they came from. Allow-list = original root.
	if n, err := Restore([]string{src}, bytes.NewReader(buf.Bytes())); err != nil || n != 2 {
		t.Fatalf("Restore round-trip n=%d err=%v", n, err)
	}
	if got, _ := os.ReadFile(filepath.Join(src, "sub/b.json")); string(got) != "b" {
		t.Fatalf("round-trip lost content, got %q", got)
	}

	// Flip a byte in the body — MD5 must catch it BEFORE the GCM check.
	bad := append([]byte(nil), buf.Bytes()...)
	bad[len(bad)-5] ^= 0xff
	if _, err := Restore([]string{src}, bytes.NewReader(bad)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("flipped-byte restore: want ErrCorrupt, got %v", err)
	}

	if _, err := Restore([]string{src}, bytes.NewReader([]byte("not a backup at all"))); !errors.Is(err, ErrNotBackup) {
		t.Fatalf("non-backup blob: want ErrNotBackup, got %v", err)
	}

	// Allowlist guard: restore with a NARROWER root must silently drop the
	// out-of-scope entries (no error, but count=0 for src-rooted entries that
	// don't fit a different root).
	other := t.TempDir()
	if n, err := Restore([]string{other}, bytes.NewReader(buf.Bytes())); err != nil || n != 0 {
		t.Fatalf("allowlist guard: want 0 restored under foreign root, got n=%d err=%v", n, err)
	}
}
