package awg

import (
	"context"
	"fmt"
	"strings"
)

// Step is one provisioning step shown in the deploy log.
type Step struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// DeployResult is the structured outcome of a server deploy.
type DeployResult struct {
	OK        bool   `json:"ok"`
	Method    string `json:"method"`
	WANIface  string `json:"wan_iface"`
	Listening bool   `json:"listening"`
	Handshake bool   `json:"handshake"`
	Steps     []Step `json:"steps"`
	Error     string `json:"error,omitempty"`
}

// runner is the seam the SSH Client implements; tests inject a fake.
type runner interface {
	Run(ctx context.Context, cmd string) (stdout, stderr string, err error)
	Put(ctx context.Context, path string, mode uint32, data []byte) error
	Close() error
}

// Deploy provisions the AmneziaWG 2.0 server on r (idempotent & re-runnable).
// It mutates c.WANIface (auto-detected) and c.Endpoint (normalized). The caller
// is responsible for having generated/persisted the server keys beforehand.
func Deploy(ctx context.Context, r runner, c *ServerConfig, progress func(Step)) DeployResult {
	c.Normalize()
	res := DeployResult{Method: c.Install}
	emit := func(s Step) {
		res.Steps = append(res.Steps, s)
		if progress != nil {
			progress(s)
		}
	}
	step := func(name, cmd string) (string, bool) {
		out, errOut, err := r.Run(ctx, cmd)
		detail := lastLinesAWG(strings.TrimSpace(out)+"\n"+strings.TrimSpace(errOut), 6)
		if err != nil && strings.TrimSpace(detail) == "" {
			detail = err.Error()
		}
		emit(Step{Name: name, OK: err == nil, Detail: redact(detail)})
		return out, err == nil
	}

	// 1. detect WAN iface / OS / virt
	if out, _ := step("detect", "ip route show default | awk '/default/{print $5; exit}'; echo '==='; . /etc/os-release 2>/dev/null; echo \"$ID $VERSION_ID\"; systemd-detect-virt 2>/dev/null || true"); true {
		if w := firstField(out); w != "" {
			c.WANIface = w
			res.WANIface = w
		}
	}

	// 2. install (apt primary, userspace fallback if DKMS module is absent)
	method := c.Install
	if method == "apt" {
		_, aptOK := step("install (apt)", aptInstallScript())
		// A DKMS module that is *registered* but failed to build still can't create
		// the interface, so require modinfo to find a loadable module — otherwise
		// fall back to userspace (apt usually still installed the awg tools).
		modOut, _ := step("verify module", "modprobe amneziawg 2>/dev/null; modinfo amneziawg >/dev/null 2>&1 && echo loaded || echo missing")
		if !aptOK || !strings.Contains(modOut, "loaded") {
			method = "userspace"
		}
	}
	if method == "userspace" {
		step("install (userspace)", userspaceInstallScript())
	}
	res.Method = method

	// 3. ip forwarding (persistent)
	step("forwarding", "sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf; echo ok")

	// 4. write server conf (secrets via stdin, 0600)
	confPath := "/etc/amnezia/amneziawg/" + c.Interface + ".conf"
	if err := r.Put(ctx, confPath, 0o600, []byte(ServerConf(c))); err != nil {
		emit(Step{Name: "write conf", OK: false, Detail: "не удалось записать конфигурацию"})
		res.Error = "не удалось записать конфигурацию на сервер"
		return res
	}
	emit(Step{Name: "write conf", OK: true, Detail: confPath})

	// 5. bring up (syncconf if already up, else enable the systemd unit)
	step("bring up", bringUpScript(c.Interface))

	// 6. verify (interface up, listening, handshake best-effort)
	out, _ := step("verify", fmt.Sprintf("awg show %s 2>&1 | head -8; echo '==LISTEN=='; (ss -lun 2>/dev/null || netstat -lun 2>/dev/null) | grep ':%d' || echo none", c.Interface, c.ListenPort))
	res.Listening = strings.Contains(out, fmt.Sprintf(":%d", c.ListenPort))
	res.Handshake = strings.Contains(out, "latest handshake")
	res.OK = res.Listening
	if !res.OK && res.Error == "" {
		res.Error = "сервер не слушает UDP-порт после деплоя (см. шаги)"
	}
	return res
}

func aptInstallScript() string {
	return strings.Join([]string{
		"export DEBIAN_FRONTEND=noninteractive",
		"if command -v awg-quick >/dev/null 2>&1 && (modinfo amneziawg >/dev/null 2>&1); then echo 'already installed'; exit 0; fi",
		"apt-get update -y >/dev/null 2>&1 || apt-get update -y",
		"apt-get install -y software-properties-common ca-certificates iproute2 iptables >/dev/null 2>&1 || true",
		"add-apt-repository -y ppa:amnezia/ppa 2>&1 || true",
		"apt-get update -y >/dev/null 2>&1 || apt-get update -y",
		"apt-get install -y \"linux-headers-$(uname -r)\" amneziawg 2>&1 || apt-get install -y amneziawg 2>&1 || true",
		"command -v awg-quick >/dev/null 2>&1 && echo 'apt install ok' || (echo 'apt install failed'; exit 1)",
	}, "\n")
}

// userspaceInstallScript is the DKMS-failure fallback: prebuilt amneziawg-tools
// (usually already installed by the apt PPA) + a from-source amneziawg-go built
// with a fetched modern Go (the distro Go is older than amneziawg-go requires).
func userspaceInstallScript() string {
	return strings.Join([]string{
		"export DEBIAN_FRONTEND=noninteractive",
		"apt-get update -y >/dev/null 2>&1 || true",
		"apt-get install -y iproute2 iptables curl unzip ca-certificates git make >/dev/null 2>&1 || true",
		// awg / awg-quick: usually present from the apt PPA; else the prebuilt zip.
		"if ! command -v awg >/dev/null 2>&1; then",
		"  T=1.0.20250901; cd /tmp || exit 1",
		"  curl -fsSLO \"https://github.com/amnezia-vpn/amneziawg-tools/releases/download/v${T}/ubuntu-22.04-amneziawg-tools.zip\" 2>&1 || true",
		"  [ -f ubuntu-22.04-amneziawg-tools.zip ] && unzip -j -o ubuntu-22.04-amneziawg-tools.zip -d awgtools >/dev/null 2>&1 || true",
		"  [ -f awgtools/awg ] && install -m755 awgtools/awg /usr/bin/awg && install -m755 awgtools/awg-quick /usr/bin/awg-quick || true",
		"fi",
		// amneziawg-go (userspace daemon) requires Go >= 1.24; fetch a modern Go and
		// build it from source, then it lives on PATH for awg-quick's userspace path.
		"if ! command -v amneziawg-go >/dev/null 2>&1; then",
		"  GOV=1.24.4; A=$(dpkg --print-architecture 2>/dev/null || echo amd64); case \"$A\" in amd64|arm64) ;; *) A=amd64 ;; esac",
		"  if ! /usr/local/go/bin/go version 2>/dev/null | grep -qE 'go1[.](2[4-9]|[3-9][0-9])'; then",
		"    curl -fsSL \"https://go.dev/dl/go${GOV}.linux-${A}.tar.gz\" -o /tmp/go.tgz && rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz; fi",
		"  rm -rf /tmp/awg-go && git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-go /tmp/awg-go 2>&1 | tail -1",
		"  (cd /tmp/awg-go && /usr/local/go/bin/go build -trimpath -ldflags '-s -w' -o /usr/bin/amneziawg-go .) 2>&1 | tail -3",
		"fi",
		"command -v awg >/dev/null 2>&1 && command -v amneziawg-go >/dev/null 2>&1 && echo 'userspace ok' || (echo 'userspace install incomplete'; exit 1)",
	}, "\n")
}

func bringUpScript(iface string) string {
	return fmt.Sprintf(`if ip link show %[1]s >/dev/null 2>&1; then awg-quick strip %[1]s > /tmp/awg-%[1]s.sync 2>/dev/null && awg syncconf %[1]s /tmp/awg-%[1]s.sync 2>&1; rm -f /tmp/awg-%[1]s.sync; else (systemctl enable --now awg-quick@%[1]s 2>&1 || awg-quick up %[1]s 2>&1); fi; echo bring-up-done`, iface)
}

func lastLinesAWG(s string, n int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}

func firstField(s string) string {
	line := strings.TrimSpace(s)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	f := strings.Fields(line)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}
