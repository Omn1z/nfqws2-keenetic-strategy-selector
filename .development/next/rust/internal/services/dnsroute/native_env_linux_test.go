//go:build linux

package dnsroute

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeNDMCChildUsesFirmwareLibrariesOnly(t *testing.T) {
	const parentPath = "/nonexistent-n2s-entware-libraries"
	t.Setenv("LD_LIBRARY_PATH", parentPath)
	for _, name := range []string{"ndmc", "other-tool"} {
		binary := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(binary, []byte("#!/bin/sh\nprintf '%s' \"$LD_LIBRARY_PATH\"\n"), 0700); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		got, err := runCommandContext(ctx, "", binary)
		cancel()
		want := parentPath
		if name == "ndmc" {
			want = "/lib:/usr/lib"
		}
		if err != nil || got != want {
			t.Fatalf("%s environment=%q, want %q; error=%v", name, got, want, err)
		}
		if os.Getenv("LD_LIBRARY_PATH") != parentPath {
			t.Fatal("child invocation changed service environment")
		}
	}
}
