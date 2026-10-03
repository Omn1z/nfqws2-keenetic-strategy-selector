//go:build linux

package arpspoof

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNDMCReportsNativeErrorEvenWithExitZero(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "ndmc")
	script := "#!/bin/sh\nprintf '%s\\n' 'Command::Base error[7405602]: argument parse error.'\nexit 0\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := runNDMC(binary, "show interface Bridge0"); err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("zero-exit native failure treated as success: %v", err)
	}
}

func TestNDMCExecPassesOneCommandArgument(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "ndmc")
	script := "#!/bin/sh\n[ \"$#\" = 2 ] && [ \"$1\" = '-c' ] || exit 2\nprintf '%s\\n' \"$2\"\n"
	if err := os.WriteFile(binary, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	command := "show interface Bridge0"
	out, err := runNDMC(binary, command)
	if err != nil || out != command {
		t.Fatalf("unexpected native exec: %q %v", out, err)
	}
}
