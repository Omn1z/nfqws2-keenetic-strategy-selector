package nfqws2

import "testing"

func TestParseAPKPackageVersion(t *testing.T) {
	const pkg = "nfqws2-keenetic"
	t.Run("policy", func(t *testing.T) {
		got := parseAPKPackageVersion("nfqws2-keenetic policy:\n  1.2.8:\n    lib/apk/db/installed\n", pkg)
		if got != "1.2.8" {
			t.Fatalf("version = %q, want 1.2.8", got)
		}
	})
	t.Run("installed wins over repository candidate", func(t *testing.T) {
		output := "nfqws2-keenetic policy:\n  1.3.0:\n    https://example.invalid/packages.adb\n  1.2.8:\n    lib/apk/db/installed\n"
		if got := parseAPKPackageVersion(output, pkg); got != "1.2.8" {
			t.Fatalf("version = %q, want installed 1.2.8", got)
		}
	})
	t.Run("info fallback", func(t *testing.T) {
		got := parseAPKPackageVersion("nfqws2-keenetic policy:\n  1.2.8:\n    lib/apk/db/installed\n", pkg)
		if got != "1.2.8" {
			t.Fatalf("version = %q, want 1.2.8", got)
		}
	})
	t.Run("candidate without local database is not installed", func(t *testing.T) {
		output := "nfqws2-keenetic policy:\n  1.3.0:\n    https://example.invalid/packages.adb\n"
		if got := parseAPKInstalledVersion(output); got != "" {
			t.Fatalf("candidate version = %q, want empty", got)
		}
	})
}
