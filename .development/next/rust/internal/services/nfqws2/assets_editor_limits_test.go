package nfqws2

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyEditorRejectsOversizedPlainAndGzipWithoutTruncation(t *testing.T) {
	m := archiveTestManager(t)
	oversized := bytes.Repeat([]byte("a"), readCap+1)
	putTestAsset(t, m, "lists/large.list", oversized)
	got, err := m.Read("list", "large.list")
	if err == nil || got != "" || !strings.Contains(err.Error(), "8 МиБ") {
		t.Fatalf("plain read returned partial content: len=%d error=%v", len(got), err)
	}
	if got, _, err := m.Bytes("list", "large.list"); err == nil || got != nil {
		t.Fatalf("download returned partial content: len=%d error=%v", len(got), err)
	}
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	if _, err = zw.Write(oversized); err != nil {
		t.Fatal(err)
	}
	if err = zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(m.assetRoots()["list"], "large-gzip.list.gz"), compressed.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	if got, err = m.Read("list", "large-gzip.list"); err == nil || got != "" {
		t.Fatalf("gzip read returned partial content: len=%d error=%v", len(got), err)
	}
	putTestAsset(t, m, "lists/upload.list", []byte("original.test\n"))
	if err = m.Upload("list", "upload.list.gz", compressed.Bytes()); err == nil {
		t.Fatal("oversized decompressed upload accepted")
	}
	if string(readTestAsset(t, m, "lists/upload.list")) != "original.test\n" {
		t.Fatal("failed upload replaced original")
	}
}

func TestLegacyEditorAcceptsExactLimitAndRejectsBrokenGzip(t *testing.T) {
	data := bytes.Repeat([]byte("a"), readCap)
	got, err := readEditorLimited(bytes.NewReader(data))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("exact read limit rejected: %v", err)
	}
	m := archiveTestManager(t)
	putTestAsset(t, m, "lists/upload.list", []byte("original.test\n"))
	if err = m.Upload("list", "upload.list.gz", []byte{0x1f, 0x8b, 0, 0}); err == nil {
		t.Fatal("broken gzip accepted as raw text")
	}
	if string(readTestAsset(t, m, "lists/upload.list")) != "original.test\n" {
		t.Fatal("broken gzip damaged original")
	}
}
