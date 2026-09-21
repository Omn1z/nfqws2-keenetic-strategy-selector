// Package path resolves the router's platform-dependent filesystem layout.
//
// The process creates one immutable Resolver at startup. Callers use Path for
// cheap lookups instead of probing /opt and /etc in every service or request.
// NewAt is intentionally exposed for hermetic tests and migration checks.
package path

import (
	"os"
	"path/filepath"
)

// Platform identifies the two supported local router layouts.
type Platform uint8

const (
	PlatformEntware Platform = iota
	PlatformOpenWrt
)

// Key identifies a stable application path. Keep platform policy here; users
// of this package should not need to know whether a target lives below /opt.
type Key string

const (
	DataDir           Key = "data_dir"
	Nfqws2Conf        Key = "nfqws2_conf"
	Nfqws2Bin         Key = "nfqws2_bin"
	Nfqws2Dir         Key = "nfqws2_dir"
	Nfqws2ListsDir    Key = "nfqws2_lists_dir"
	Nfqws2LuaDir      Key = "nfqws2_lua_dir"
	Nfqws2BlobsDir    Key = "nfqws2_blobs_dir"
	Nfqws2Init        Key = "nfqws2_init"
	Nfqws2PID         Key = "nfqws2_pid"
	StrategyBin       Key = "strategy_bin"
	StrategyOldBin    Key = "strategy_old_bin"
	StrategyInit      Key = "strategy_init"
	StrategyRunDir    Key = "strategy_run_dir"
	StrategyLogDir    Key = "strategy_log_dir"
	AWGEngineDir      Key = "awg_engine_dir"
	AWGConfigDir      Key = "awg_config_dir"
	AWGSetDir         Key = "awg_set_dir"
	AWGListsDir       Key = "awg_lists_dir"
	AWGHook           Key = "awg_hook"
	AWGMultiHook      Key = "awg_multi_hook"
	AWGFW4Hook        Key = "awg_fw4_hook"
	AWGLegacyWatchdog Key = "awg_legacy_watchdog"
	NFQWSBypass       Key = "nfqws_bypass"
	NFQWSBypassFW4    Key = "nfqws_bypass_fw4"
	PortForwardHook   Key = "port_forward_hook"
	DNSHook           Key = "dns_hook"
	ARPSpoofHook      Key = "arp_spoof_hook"
	TcpdumpOptDir     Key = "tcpdump_opt_dir"
	TcpdumpSystemDir  Key = "tcpdump_system_dir"
	EtcDir            Key = "etc_dir"
	AuthEtcDir        Key = "auth_etc_dir"
	EntwareOpkg       Key = "entware_opkg"
)

// Resolver is immutable after construction and safe for concurrent use.
// Values are precomputed once, including legacy AWG fallback checks.
type Resolver struct {
	platform Platform
	root     string
	values   map[Key]string
}

// New resolves the live router layout once.
func New() *Resolver { return NewAt("/") }

// NewAt resolves a layout below root. root="/" is the production layout;
// another root is useful for tests and migration simulations.
func NewAt(root string) *Resolver {
	if root == "" {
		root = "/"
	}
	root = filepath.Clean(root)

	isOpenWrt := exists(root, "/etc/openwrt_release") || exists(root, "/etc/rc.common")
	platform := PlatformEntware
	if isOpenWrt {
		platform = PlatformOpenWrt
	}

	opt := func(p string) string { return rooted(root, p) }
	values := map[Key]string{
		EtcDir:           opt("/etc"),
		AuthEtcDir:       opt("/etc"),
		StrategyRunDir:   opt("/var/run"),
		StrategyLogDir:   opt("/var/log"),
		TcpdumpOptDir:    opt("/opt"),
		TcpdumpSystemDir: opt("/usr/sbin"),
		EntwareOpkg:      opt("/opt/bin/opkg"),
	}
	if platform == PlatformOpenWrt {
		values[DataDir] = opt("/etc/nfqws2-strategy")
		values[Nfqws2Conf] = opt("/etc/nfqws2/nfqws2.conf")
		values[Nfqws2Bin] = opt("/usr/bin/nfqws2")
		values[Nfqws2Dir] = opt("/etc/nfqws2")
		values[Nfqws2ListsDir] = opt("/etc/nfqws2/lists")
		values[Nfqws2LuaDir] = opt("/etc/nfqws2/lua")
		values[Nfqws2BlobsDir] = opt("/etc/nfqws2/blobs")
		values[Nfqws2Init] = opt("/etc/init.d/nfqws2-keenetic")
		values[Nfqws2PID] = opt("/var/run/nfqws2.pid")
		values[StrategyBin] = opt("/usr/bin/n2s")
		values[StrategyOldBin] = opt("/usr/bin/nfqws2-strategy")
		values[StrategyInit] = opt("/etc/init.d/nfqws2-strategy")
		values[AWGSetDir] = opt("/etc/nfqws2-strategy")
		values[AWGListsDir] = opt("/etc/nfqws2/lists")
		values[AWGHook] = opt("/etc/nfqws2-strategy/90-awg2.sh")
		values[AWGMultiHook] = opt("/etc/nfqws2-strategy/91-awg2-multi.sh")
		values[AWGFW4Hook] = opt("/etc/nfqws2-strategy/92-awg2-fw4.sh")
		values[AWGLegacyWatchdog] = ""
		values[NFQWSBypass] = opt("/etc/nfqws2/nfqws-bypass.sh")
		values[NFQWSBypassFW4] = opt("/etc/nfqws2/nfqws-bypass-fw4.sh")
		values[PortForwardHook] = opt("/etc/nfqws2-strategy/91-n2s-port-forward.sh")
		values[DNSHook] = opt("/etc/nfqws2-strategy/93-nfqws-dns.sh")
		values[ARPSpoofHook] = opt("/etc/nfqws2-strategy/92-n2s-arp-spoof.sh")

		// OpenWrt installations from the first migration can still have a
		// working Entware AWG binary/config. Preserve it until the next install.
		values[AWGEngineDir] = firstExistingDir(root, "/usr/bin", "/opt/usr/bin", "amneziawg-go")
		values[AWGConfigDir] = firstExistingDir(root, "/etc/amnezia/amneziawg", "/opt/etc/amnezia/amneziawg", "")
	} else {
		values[AuthEtcDir] = opt("/opt/etc")
		values[DataDir] = opt("/opt/etc/nfqws2-strategy")
		values[Nfqws2Conf] = opt("/opt/etc/nfqws2/nfqws2.conf")
		values[Nfqws2Bin] = opt("/opt/usr/bin/nfqws2")
		values[Nfqws2Dir] = opt("/opt/etc/nfqws2")
		values[Nfqws2ListsDir] = opt("/opt/etc/nfqws2/lists")
		values[Nfqws2LuaDir] = opt("/opt/etc/nfqws2/lua")
		values[Nfqws2BlobsDir] = opt("/opt/etc/nfqws2/blobs")
		values[Nfqws2Init] = opt("/opt/etc/init.d/S51nfqws2")
		values[Nfqws2PID] = opt("/opt/var/run/nfqws2.pid")
		values[StrategyBin] = opt("/opt/usr/bin/n2s")
		values[StrategyOldBin] = opt("/opt/usr/bin/nfqws2-strategy")
		values[StrategyInit] = opt("/opt/etc/init.d/S52nfqws2-strategy")
		values[StrategyRunDir] = opt("/opt/var/run")
		values[StrategyLogDir] = opt("/opt/var/log")
		values[AWGEngineDir] = opt("/opt/usr/bin")
		values[AWGConfigDir] = opt("/opt/etc/amnezia/amneziawg")
		values[AWGSetDir] = opt("/opt/etc/nfqws2-strategy")
		values[AWGListsDir] = opt("/opt/etc/nfqws2/lists")
		values[AWGHook] = opt("/opt/etc/ndm/netfilter.d/90-awg2.sh")
		values[AWGMultiHook] = opt("/opt/etc/ndm/netfilter.d/91-awg2-multi.sh")
		values[AWGFW4Hook] = opt("/opt/etc/ndm/netfilter.d/92-awg2-fw4.sh")
		values[AWGLegacyWatchdog] = opt("/opt/etc/init.d/S53awg1-watchdog")
		values[NFQWSBypass] = opt("/opt/etc/nfqws2/nfqws-bypass.sh")
		values[NFQWSBypassFW4] = ""
		values[PortForwardHook] = opt("/opt/etc/ndm/netfilter.d/91-n2s-port-forward.sh")
		values[DNSHook] = opt("/opt/etc/ndm/netfilter.d/93-nfqws-dns.sh")
		values[ARPSpoofHook] = opt("/opt/etc/ndm/netfilter.d/92-n2s-arp-spoof.sh")
	}
	return &Resolver{platform: platform, root: root, values: values}
}

func rooted(root, p string) string {
	p = filepath.FromSlash(p)
	if root == string(filepath.Separator) {
		return filepath.Clean(p)
	}
	return filepath.Join(root, p)
}

func exists(root, p string) bool {
	_, err := os.Stat(rooted(root, p))
	return err == nil
}

func firstExistingDir(root string, dirs ...string) string {
	if len(dirs) == 0 {
		return ""
	}
	marker := dirs[len(dirs)-1]
	for _, dir := range dirs[:len(dirs)-1] {
		candidate := rooted(root, dir)
		if marker == "" {
			if info, err := os.Stat(candidate); err == nil && info.IsDir() {
				return candidate
			}
			continue
		}
		if info, err := os.Stat(filepath.Join(candidate, marker)); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	return rooted(root, dirs[0])
}

// Platform reports the cached platform.
func (r *Resolver) Platform() Platform { return r.platform }

// IsOpenWrt reports whether this resolver targets OpenWrt.
func (r *Resolver) IsOpenWrt() bool { return r.platform == PlatformOpenWrt }

// Path returns a resolved path and optionally appends path components. Unknown
// keys return an empty string, making unsupported platform features explicit.
func (r *Resolver) Path(key Key, parts ...string) string {
	base := r.values[key]
	if base == "" {
		return ""
	}
	if len(parts) == 0 {
		return base
	}
	all := make([]string, 1, len(parts)+1)
	all[0] = base
	all = append(all, parts...)
	return filepath.Join(all...)
}

var global = New()

// Current returns the process-wide immutable resolver.
func Current() *Resolver { return global }

// Path is the fast process-wide lookup used by runtime code.
func Path(key Key, parts ...string) string { return global.Path(key, parts...) }

// Platform reports the process-wide platform.
func PlatformOf() Platform { return global.Platform() }

// IsOpenWrt reports the process-wide platform.
func IsOpenWrt() bool { return global.IsOpenWrt() }
