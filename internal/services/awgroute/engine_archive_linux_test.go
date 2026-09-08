//go:build linux

package awgroute

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func testEngineArchive(t *testing.T, body []byte, flag byte, copies int) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for i := 0; i < copies; i++ {
		h := &tar.Header{Name: "./amneziawg-go", Mode: 0o755, Typeflag: flag, Size: int64(len(body))}
		if flag == tar.TypeSymlink {
			h.Linkname = "other-file"
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := tw.Write(body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestEngineArchiveRejectsInvalidWithoutReplacement(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"not gzip", []byte("not an archive")},
		{"missing executable", testEngineArchive(t, nil, tar.TypeReg, 0)},
		{"not an executable", testEngineArchive(t, []byte("not a Go executable"), tar.TypeReg, 1)},
		{"symlink", testEngineArchive(t, nil, tar.TypeSymlink, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "amneziawg-go")
			if err := os.WriteFile(path, []byte("previous engine"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := extractEngine(tc.data, dir); err == nil {
				t.Fatal("accepted invalid archive")
			}
			if b, err := os.ReadFile(path); err != nil || string(b) != "previous engine" {
				t.Fatal("working engine was replaced")
			}
		})
	}
}

// Optional integration fixture: the official build for the test host's arch.
func TestEngineArchiveOfficialBuild(t *testing.T) {
	fixture := os.Getenv("AWG_ENGINE_TEST_BINARY")
	if fixture == "" {
		t.Skip("set AWG_ENGINE_TEST_BINARY for official-build archive verification")
	}
	body, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	valid := testEngineArchive(t, body, tar.TypeReg, 1)
	corrupt := append([]byte{}, valid...)
	corrupt[len(corrupt)-8] ^= 1
	for _, tc := range []struct {
		name string
		data []byte
		ok   bool
	}{
		{"valid", valid, true},
		{"bad gzip footer", corrupt, false},
		{"duplicate executable", testEngineArchive(t, body, tar.TypeReg, 2), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "amneziawg-go")
			if err := os.WriteFile(path, []byte("previous engine"), 0o755); err != nil {
				t.Fatal(err)
			}
			err := extractEngine(tc.data, dir)
			if (err == nil) != tc.ok {
				t.Fatalf("unexpected result: %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if tc.ok && !bytes.Equal(got, body) {
				t.Fatal("installed executable differs")
			}
			if !tc.ok && string(got) != "previous engine" {
				t.Fatal("working engine changed after rejected archive")
			}
		})
	}
}
