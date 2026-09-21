package config

import (
	"os"
	"regexp"
	"strings"

	routerpath "nfqws2strategy/internal/tools/path"
)

// Config holds runtime configuration. Most networking-related fields are
// auto-derived from the installed nfqws2 setup so the tester stays in sync
// with the user's environment (interfaces, base lua libs, custom blobs).
type Config struct {
	ListenAddr     string   `json:"listen_addr"`
	DataDir        string   `json:"data_dir"`
	Nfqws2Conf     string   `json:"nfqws2_conf"`
	NfqwsBin       string   `json:"nfqws_bin"`
	WANIfaces      []string `json:"wan_ifaces"`
	BaseArgs       []string `json:"base_args"`
	SystemBlobsDir string   `json:"system_blobs_dir"`
	LuaDir         string   `json:"lua_dir"`

	// Self-update.
	Version    string `json:"version"`
	Repo       string `json:"repo"`        // owner/name on GitHub
	InitScript string `json:"init_script"` // OUR service control script (S52, restart after update)
	Nfqws2Init string `json:"nfqws2_init"` // upstream nfqws2 service init (S51, for the restart button)

	// nfqws2 engine package (for the NFQWS2 tab's version display + opkg update).
	Nfqws2Repo string `json:"nfqws2_repo"` // GitHub owner/name of the engine package
	Nfqws2Pkg  string `json:"nfqws2_pkg"`  // opkg package name of the engine

	// Worker sandbox parameters.
	FirstQueue     int `json:"first_queue"`
	PortBase       int `json:"port_base"`
	PortsPerWorker int `json:"ports_per_worker"`

	// MainQueue is the NFQUEUE the live nfqws2 service binds (for the dashboard
	// "packets" card). Distinct from FirstQueue, which is the test-sandbox base.
	MainQueue int `json:"main_queue"`
}

func Default() *Config {
	c := &Config{
		ListenAddr:     ":8090",
		DataDir:        routerpath.Path(routerpath.DataDir),
		Nfqws2Conf:     routerpath.Path(routerpath.Nfqws2Conf),
		NfqwsBin:       routerpath.Path(routerpath.Nfqws2Bin),
		WANIfaces:      []string{"eth3"},
		SystemBlobsDir: routerpath.Path(routerpath.Nfqws2BlobsDir),
		LuaDir:         routerpath.Path(routerpath.Nfqws2LuaDir),
		FirstQueue:     200,
		PortBase:       50000,
		PortsPerWorker: 200,
		MainQueue:      300,
		InitScript:     routerpath.Path(routerpath.StrategyInit),
		Nfqws2Init:     routerpath.Path(routerpath.Nfqws2Init),
		Nfqws2Repo:     "nfqws/nfqws2-keenetic",
		Nfqws2Pkg:      "nfqws2-keenetic",
	}
	return c
}

// Anchored at line start (multiline) so commented-out example lines like
// `# ... ISP_INTERFACE="eth3 nwg1"` are not matched instead of the real value.
var (
	reBase  = regexp.MustCompile(`(?m)^[ \t]*NFQWS_BASE_ARGS="([^"]*)"`)
	reIface = regexp.MustCompile(`(?m)^[ \t]*ISP_INTERFACE="([^"]*)"`)
)

// LoadFromNfqws2Conf reads ISP_INTERFACE and NFQWS_BASE_ARGS from the installed
// nfqws2.conf to keep the tester aligned with the live setup. Missing file is a
// soft error the caller may ignore (defaults remain).
func (c *Config) LoadFromNfqws2Conf() error {
	b, err := os.ReadFile(c.Nfqws2Conf)
	if err != nil {
		return err
	}
	s := string(b)
	if m := reIface.FindStringSubmatch(s); m != nil {
		if f := strings.Fields(m[1]); len(f) > 0 {
			c.WANIfaces = f
		}
	}
	if m := reBase.FindStringSubmatch(s); m != nil {
		c.BaseArgs = splitArgs(m[1])
	}
	return nil
}

// splitArgs flattens a multi-line shell arg blob into tokens, dropping blank and
// #comment lines.
func splitArgs(blob string) []string {
	var out []string
	for _, line := range strings.Split(blob, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.Fields(line)...)
	}
	return out
}
