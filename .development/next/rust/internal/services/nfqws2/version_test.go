package nfqws2

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestNFQWS2VersionKeepsPackageAndBinarySeparate(t *testing.T) {
	for _, tc := range []struct {
		name, pm, output, wantPackage, wantStatus string
		apk                                       bool
		err                                       error
	}{
		{"Entware installed", "/opt/bin/opkg", "Package: nfqws2-keenetic\nVersion: 1.3.1\nStatus: install user installed\n", "1.3.1", packageInstalled, false, nil},
		{"OpenWrt 24 revision", "opkg", "Package: nfqws2-keenetic\nVersion: 1.3.1-1\nStatus: install ok installed\n", "1.3.1-1", packageInstalled, false, nil},
		{"OpenWrt 25 revision", "apk", "nfqws2-keenetic policy:\n  1.3.2-r0:\n    https://example.test/packages.adb\n  1.3.1-r1:\n    lib/apk/db/installed\n", "1.3.1-r1", packageInstalled, true, nil},
		{"opkg absent, manual binary", "opkg", "", "", packageMissing, false, nil},
		{"apk candidate only, manual binary", "apk", "nfqws2-keenetic policy:\n  1.3.1:\n    https://example.test/packages.adb\n", "", packageMissing, true, nil},
		{"opkg timeout", "opkg", "", "", packageUnknown, false, context.DeadlineExceeded},
		{"apk timeout", "apk", "", "", packageUnknown, true, context.DeadlineExceeded},
		{"opkg partial output on failure", "opkg", "Package: nfqws2-keenetic\nVersion: 1.2.8\nStatus: install user installed\n", "", packageUnknown, false, errors.New("database unavailable")},
		{"apk partial output on failure", "apk", "nfqws2-keenetic policy:\n  1.2.8:\n    lib/apk/db/installed\n", "", packageUnknown, true, errors.New("database unavailable")},
		{"no package manager, manual binary", "", "", "", packageUnknown, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var packageCtx context.Context
			calls := 0
			info := readVersion(tc.pm, tc.apk, "nfqws2-keenetic", "/usr/bin/nfqws2", func(ctx context.Context, bin string, args ...string) ([]byte, error) {
				calls++
				if bin == tc.pm {
					packageCtx = ctx
					wantArgs := []string{"status", "nfqws2-keenetic"}
					if tc.apk {
						wantArgs[0] = "policy"
					}
					if !reflect.DeepEqual(args, wantArgs) {
						t.Fatalf("package command args = %v, want %v", args, wantArgs)
					}
					return []byte(tc.output), tc.err
				}
				if bin != "/usr/bin/nfqws2" || !reflect.DeepEqual(args, []string{"--version"}) {
					t.Fatalf("unexpected command %s %v", bin, args)
				}
				if packageCtx != nil && packageCtx.Err() == nil {
					t.Fatal("package context was not released before binary probe")
				}
				if ctx.Err() != nil {
					t.Fatal("package query consumed the binary probe's context")
				}
				return []byte("github version v1.0.5.2 (commit) lua_compat_ver 6\n"), nil
			})
			if info.Package != tc.wantPackage || info.PackageStatus != tc.wantStatus || info.Engine != "v1.0.5.2" {
				t.Fatalf("version info = %+v", info)
			}
			if (info.Error != "") != (tc.wantStatus == packageUnknown) {
				t.Fatalf("wrong query error: %+v", info)
			}
			info.applyRelease("v1.3.1", "https://example.test/release")
			if info.Available {
				t.Fatalf("same release or unknown/manual installation offered as update: %+v", info)
			}
			wantCalls := 2
			if tc.pm == "" {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatalf("ran %d commands, want %d", calls, wantCalls)
			}
		})
	}
}

func TestNFQWS2PackageReleaseOrdering(t *testing.T) {
	for _, tc := range []struct {
		current, latest string
		available       bool
	}{
		{"1.3.1", "v1.3.1", false},
		{"v1.3.1", "1.3.1", false},
		{"1.3.1-1", "v1.3.1", false},
		{"1.3.1-r0", "v1.3.1", false},
		{"1.3.1-r2", "v1.3.1-r1", false},
		{"1.3.1-r1", "v1.3.1-r2", true},
		{"1.3.1-9", "v1.3.1-10", true},
		{"1.3.1-r3", "v1.3.1-3", false},
		{"1.3.1", "v1.2.8", false},
		{"1.2.8", "v1.3.1", true},
		{"1.3.9", "v1.3.10", true},
		{"1.3.10", "v1.3.9", false},
		{"1.3.1-r9", "v1.3.2-r0", true},
		{"1.3.2-rc.1", "v1.3.2", true},
		{"1.3.2", "v1.3.2-rc.1", false},
		{"1.3.1", "invalid", false},
		{"invalid", "v1.3.1", false},
		{"1.3.1", "", false},
		{"", "v1.3.1", false},
	} {
		t.Run(tc.current+" to "+tc.latest, func(t *testing.T) {
			info := VersionInfo{Package: tc.current, Engine: "v0.9.5.1", PackageStatus: packageInstalled, Available: true}
			info.applyRelease(tc.latest, "https://example.test/release")
			if info.Available != tc.available {
				t.Fatalf("available = %v, want %v; %+v", info.Available, tc.available, info)
			}
		})
	}
}

func TestNFQWS2FreshInstallAndUnknownState(t *testing.T) {
	for _, tc := range []struct {
		name, status, engine string
		available            bool
	}{
		{"fresh package installation", packageMissing, "", true},
		{"manual binary remains installed", packageMissing, "v1.0.5.2", false},
		{"query failure is not absent", packageUnknown, "", false},
		{"binary version cannot repair query failure", packageUnknown, "v1.0.5.2", false},
		{"zero value is not absent", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := VersionInfo{PackageStatus: tc.status, Engine: tc.engine}
			info.applyRelease("v1.3.1", "https://example.test/release")
			if info.Available != tc.available || info.Package != "" {
				t.Fatalf("unexpected availability/package: %+v", info)
			}
		})
	}
}

func TestNFQWS2InstalledPackageParsers(t *testing.T) {
	const pkg = "nfqws2-keenetic"
	for _, tc := range []struct {
		name, output, version string
		apk, wantError        bool
	}{
		{"opkg CRLF", "Package: nfqws2-keenetic\r\nVersion: 1.3.1\r\nStatus: install user installed\r\n", "1.3.1", false, false},
		{"opkg residual config", "Package: nfqws2-keenetic\nVersion: 1.3.1\nStatus: deinstall ok config-files\n", "", false, false},
		{"opkg missing installed version", "Package: nfqws2-keenetic\nStatus: install user installed\n", "", false, true},
		{"opkg incomplete status", "Package: nfqws2-keenetic\nVersion: 1.3.1\n", "", false, true},
		{"opkg diagnostic instead of record", "opkg: cannot read database", "", false, true},
		{"opkg unrelated record", "Package: nfqws2\nVersion: 1.0.5.2\nStatus: install user installed\n", "", false, true},
		{"opkg exact record among many", "Package: nfqws2\nVersion: 1.0.5.2\nStatus: install user installed\n\nPackage: nfqws2-keenetic\nVersion: 1.3.1\nStatus: install user installed\n", "1.3.1", false, false},
		{"apk unknown output", "ERROR: temporary package database failure", "", true, true},
		{"apk empty success", "", "", true, false},
		{"apk unrelated policy", "nfqws2 policy:\n  1.0.5:\n    lib/apk/db/installed\n", "", true, true},
		{"apk unrelated installed marker", "nfqws2-keenetic policy:\n  1.3.1:\n    https://example.test/packages.adb\nnfqws2 policy:\n  1.0.5:\n    lib/apk/db/installed\n", "", true, false},
		{"apk invalid installed version", "nfqws2-keenetic policy:\n  bad-version:\n    lib/apk/db/installed\n", "", true, true},
		{"apk invalid installed version does not fall back to candidate", "nfqws2-keenetic policy:\n  1.3.2:\n    https://example.test/packages.adb\n  bad-version:\n    lib/apk/db/installed\n", "", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parse := installedOPKGVersion
			if tc.apk {
				parse = installedAPKVersion
			}
			version, err := parse(tc.output, pkg)
			if version != tc.version || (err != nil) != tc.wantError {
				t.Fatalf("version = %q, error = %v", version, err)
			}
		})
	}
}

func TestNFQWS2PackageQueryDoesNotUseShellInterpolation(t *testing.T) {
	pkg := "package with ' spaces; $(ignored)"
	info := readVersion("opkg", false, pkg, "nfqws2", func(_ context.Context, bin string, args ...string) ([]byte, error) {
		if bin == "opkg" {
			if len(args) != 2 || args[0] != "status" || args[1] != pkg {
				t.Fatalf("package argument changed: %q", args)
			}
			return []byte("Package: " + pkg + "\nVersion: 1.3.1\nStatus: install user installed\n"), nil
		}
		return nil, errors.New("binary absent")
	})
	if info.Package != "1.3.1" || strings.Contains(info.Package, "1.0") {
		t.Fatalf("wrong package version: %+v", info)
	}
}
