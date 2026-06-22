package app

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"nfqws2strategy/internal/tools/backup"
	"nfqws2strategy/internal/tools/logbuf"
)

// BackupBuild streams a sealed archive of all selector state into w. Nothing
// is written to disk on the router — the archive goes straight to the user.
// Sealing is anti-tamper: the user can't open the file and edit individual
// values; the GCM/MD5 envelope refuses any byte-edited archive on restore.
func (a *App) BackupBuild(w io.Writer) (string, int, error) {
	n, err := backup.Build(a.backupRoots(), w)
	if err != nil {
		return "", 0, err
	}
	name := backup.Filename(time.Now())
	logbuf.Append("backup", "info", fmt.Sprintf("скачивание %s: %d файлов", name, n))
	return name, n, nil
}

// BackupRestore applies a sealed archive back onto disk. Files are written
// to the absolute paths recorded in the archive, but only if they fall under
// one of the allowed roots (same set Build captured). The caller is expected
// to trigger a selector restart after success so the new files take effect.
func (a *App) BackupRestore(r io.Reader) (int, error) {
	n, err := backup.Restore(a.backupRoots(), r)
	if err != nil {
		return n, err
	}
	logbuf.Append("backup", "info", fmt.Sprintf("восстановлено %d файлов", n))
	return n, nil
}

// backupRoots is the canonical "everything the selector owns" path set. Every
// entry is treated as an allow-list root for both build (walk) and restore
// (write). Missing entries are silently skipped — the same list is safe to
// declare even on installs that don't have every optional piece (e.g. no
// kernel-WG conf on a router-only deploy).
//
// In scope (selector state, restore makes the install whole):
//   - Selector's own DataDir — awg.json (servers+peers+private keys + PSK +
//     obfuscation Jc/Jmin/Jmax/S1/S2/H1..H4 + SSH creds + routing rules),
//     pihole.json, automation.json, lists/, runs/, geo/, custom strategies,
//     settings, ipsets (awg2_inc/exc/recent) — every file the selector reads
//     on boot.
//   - /opt/etc/amnezia/amneziawg/awg0.conf — reference copy of the AWG tunnel
//     conf written by the selector on every `up`. It's regenerated from
//     awg.json so it's a cosmetic include, but it makes a restored archive
//     identical to the live state byte-for-byte.
//   - /etc/amnezia/amneziawg/ — host-side kernel-mode AmneziaWG layout when
//     the user is on the kernel module instead of the userspace daemon.
//   - /opt/etc/ndm/netfilter.d/90-awg2.sh — Keenetic-style firewall hook the
//     selector installs to survive fw3 reloads.
//
// Out of scope (deliberately not backed up):
//   - /data/xmir-init.sh — user's personal boot script; not selector state.
//   - pi-hole's USB-mount data dir — managed by FTL itself; restoring would
//     clobber Pi-hole's own UI state.
//
// Missing paths are skipped silently inside the backup package, so listing
// every plausible location here is safe across different deployments.
func (a *App) backupRoots() []string {
	roots := []string{a.dataDir()}
	for _, p := range []string{
		"/opt/etc/amnezia/amneziawg",
		"/etc/amnezia/amneziawg",
		"/opt/etc/ndm/netfilter.d/90-awg2.sh",
	} {
		if _, err := os.Stat(p); err == nil {
			roots = append(roots, p)
		}
	}
	return dedupRoots(roots)
}

func (a *App) dataDir() string {
	if a.Cfg != nil && a.Cfg.DataDir != "" {
		return a.Cfg.DataDir
	}
	return "/opt/etc/nfqws2-strategy"
}

func dedupRoots(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, p := range in {
		abs, _ := filepath.Abs(p)
		key := strings.TrimSuffix(abs, string(filepath.Separator))
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}
