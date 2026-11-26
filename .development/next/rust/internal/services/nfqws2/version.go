package nfqws2

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

const (
	packageInstalled = "installed"
	packageMissing   = "missing"
	packageUnknown   = "unknown"
)

var (
	reEngineVer       = regexp.MustCompile(`version\s+(v?[0-9][0-9A-Za-z._-]*)`)
	rePackageRevision = regexp.MustCompile(`-(?:r)?([0-9]+)$`)
)

type versionCommand func(context.Context, string, ...string) ([]byte, error)

// Version keeps the package (nfqws2-keenetic) and binary (zapret2) version
// namespaces separate. A timeout reading the package database must never turn
// the binary version into an installed package version.
func (m *Manager) Version() VersionInfo {
	pm, apk := packageManager()
	return readVersion(pm, apk, m.cfg.Nfqws2Pkg, m.cfg.NfqwsBin, func(ctx context.Context, bin string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, bin, args...).CombinedOutput()
	})
}

func readVersion(pm string, apk bool, pkg, bin string, run versionCommand) VersionInfo {
	info := VersionInfo{PackageStatus: packageUnknown}
	if pm == "" {
		info.Error = "package manager not found (apk/opkg)"
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		args := []string{"status", pkg}
		if apk {
			args = []string{"policy", pkg}
		}
		out, err := run(ctx, pm, args...)
		cancel()
		if err == nil {
			if apk {
				info.Package, err = installedAPKVersion(string(out), pkg)
			} else {
				info.Package, err = installedOPKGVersion(string(out), pkg)
			}
		}
		if err != nil {
			info.Error = fmt.Sprintf("cannot determine installed %s package version: %v", pkg, err)
		} else if info.Package != "" {
			info.PackageStatus = packageInstalled
		} else {
			info.PackageStatus = packageMissing
		}
	}
	// Use a separate deadline: a slow package database must not consume the
	// binary probe's budget, or make a working manual installation disappear.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if out, err := run(ctx, bin, "--version"); err == nil {
		if match := reEngineVer.FindStringSubmatch(string(out)); match != nil {
			info.Engine = match[1]
		}
	}
	return info
}

func installedOPKGVersion(output, pkg string) (string, error) {
	if strings.TrimSpace(output) == "" {
		return "", nil // successful `opkg status` for an absent package
	}
	for _, record := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n\n") {
		fields := make(map[string]string)
		for _, line := range strings.Split(record, "\n") {
			if key, value, ok := strings.Cut(line, ":"); ok {
				fields[key] = strings.TrimSpace(value)
			}
		}
		if fields["Package"] != pkg {
			continue
		}
		status := strings.Fields(fields["Status"])
		if len(status) != 3 {
			return "", fmt.Errorf("invalid package status")
		}
		if status[2] != "installed" {
			return "", nil
		}
		version := fields["Version"]
		if _, _, ok := packageReleaseVersion(version); !ok {
			return "", fmt.Errorf("invalid installed package version %q", version)
		}
		return version, nil
	}
	return "", fmt.Errorf("package status did not identify %s", pkg)
}

func installedAPKVersion(output, pkg string) (string, error) {
	if strings.TrimSpace(output) == "" {
		return "", nil
	}
	// Restrict the installed database marker to the requested package section.
	// Repository candidates alone do not prove that a package is installed.
	var section []string
	found := false
	for _, line := range strings.Split(output, "\n") {
		if line != "" && line[0] != ' ' && line[0] != '\t' {
			if found {
				break
			}
			found = strings.TrimSpace(line) == pkg+" policy:"
			continue
		}
		if found {
			section = append(section, line)
		}
	}
	if !found {
		return "", fmt.Errorf("package policy did not identify %s", pkg)
	}
	policy := strings.Join(section, "\n")
	if !strings.Contains(policy, "lib/apk/db/installed") {
		return "", nil
	}
	version := parseAPKInstalledVersion(policy)
	if _, _, ok := packageReleaseVersion(version); !ok {
		return "", fmt.Errorf("invalid installed package version %q", version)
	}
	return version, nil
}

// The GitHub tag describes the upstream package release. opkg/APK additionally
// append a packaging revision, e.g. 1.3.1-1 / 1.3.1-r0. A plain 1.3.1 release
// must not be offered again merely because its installed package has a suffix.
func packageReleaseVersion(raw string) (version string, revision uint64, ok bool) {
	version = strings.TrimPrefix(strings.TrimSpace(raw), "v")
	if match := rePackageRevision.FindStringSubmatchIndex(version); match != nil {
		var err error
		revision, err = strconv.ParseUint(version[match[2]:match[3]], 10, 64)
		if err != nil {
			return "", 0, false
		}
		version = version[:match[0]]
	}
	version = "v" + version
	return version, revision, semver.IsValid(version)
}

func (info *VersionInfo) applyRelease(tag, url string) {
	info.Latest = strings.TrimPrefix(strings.TrimSpace(tag), "v")
	info.URL = url
	info.Available = false
	latest, latestRevision, valid := packageReleaseVersion(tag)
	if !valid {
		info.Error = "invalid package release version"
		return
	}
	switch info.PackageStatus {
	case packageInstalled:
		current, currentRevision, valid := packageReleaseVersion(info.Package)
		if !valid {
			info.Error = "invalid installed package version"
			return
		}
		cmp := semver.Compare(latest, current)
		info.Available = cmp > 0 || (cmp == 0 && latestRevision > currentRevision)
	case packageMissing:
		// Keep installation available on a fresh router. A manually copied
		// binary has no comparable package version and is not an update target.
		info.Available = info.Engine == ""
	}
}
