package awg

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"strings"
	"time"

	"nfqws2strategy/internal/tools/strs"
)

// Step is one provisioning step shown in the deploy log.
type Step struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// DeployResult is the structured outcome of a server deploy.
type DeployResult struct {
	OK             bool   `json:"ok"`
	Method         string `json:"method"`
	WANIface       string `json:"wan_iface"`
	Listening      bool   `json:"listening"`
	Handshake      bool   `json:"handshake"`
	Steps          []Step `json:"steps"`
	Error          string `json:"error,omitempty"`
	RollbackStatus string `json:"rollback_status,omitempty"` // "restored", "removed_new", "failed"
	RollbackError  string `json:"rollback_error,omitempty"`
	RollbackBackup string `json:"rollback_backup,omitempty"` // retained remote directory if recovery could not be confirmed
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
func Deploy(ctx context.Context, r runner, c *ServerConfig, progress func(Step), reconnect ...func(context.Context) (runner, error)) (res DeployResult) {
	c.Normalize()
	res = DeployResult{Method: c.Install}
	if errs := c.Validate(); len(errs) > 0 {
		res.Error = strings.Join(errs, "; ")
		return res
	}
	emit := func(s Step) {
		res.Steps = append(res.Steps, s)
		if progress != nil {
			progress(s)
		}
	}
	step := func(name, cmd string) (string, bool) {
		out, errOut, err := r.Run(ctx, cmd)
		detail := strs.LastLines(strings.TrimSpace(out+"\n"+errOut), 6)
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
	// The distro/PPA may still carry AWG 2.0. AWG 3.1 uses a pinned userspace
	// build and a dedicated awg-quick entry point, irrespective of loaded DKMS.
	if c.RequiresAWG31() {
		method = "userspace"
	}
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
		if _, ok := step("install (userspace)", userspaceInstallScript()); !ok {
			res.Method = method
			res.Error = "не удалось установить совместимый AmneziaWG; конфигурация сервера не изменена"
			return res
		}
	}
	res.Method = method
	if method == "userspace" {
		if _, ok := step("configure userspace service", userspaceServiceScript(c.Interface)); !ok {
			res.Error = "не удалось настроить userspace-службу AmneziaWG"
			return res
		}
	}

	// 3. ip forwarding (persistent)
	step("forwarding", "sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf; echo ok")

	// 4. Preserve the remote file before staging a replacement. A partial SSH
	// upload never truncates the active file, and all secret files remain 0600.
	confPath := "/etc/amnezia/amneziawg/" + c.Interface + ".conf"
	backupDir := "/etc/amnezia/amneziawg/.nfqws-deploy-" + c.Interface + "-" + newID()
	config := []byte(ServerConf(c))
	digest := fmt.Sprintf("%x", sha256.Sum256(config))
	backupOut, backupOK := step("backup conf", backupConfigScript(c.Interface, backupDir))
	if !backupOK || (!strings.Contains(backupOut, "previous=1") && !strings.Contains(backupOut, "previous=0")) {
		res.Error = "не удалось подтвердить резервную копию конфигурации VPS; активная конфигурация не изменена"
		res.RollbackBackup = backupDir // an interrupted SSH command may have already copied the file
		return res
	}
	hadPrevious := strings.Contains(backupOut, "previous=1")
	activationAttempted := false
	defer func() {
		recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
		defer cancel()
		runRecovery := func(name, cmd string) (string, error) {
			out, errOut, err := r.Run(recoveryCtx, cmd)
			// A broken original SSH session must not prevent a best-effort rollback.
			if err != nil && len(reconnect) > 0 && reconnect[0] != nil && recoveryCtx.Err() == nil {
				if fresh, dialErr := reconnect[0](recoveryCtx); dialErr == nil {
					out, errOut, err = fresh.Run(recoveryCtx, cmd)
					_ = fresh.Close()
				} else {
					err = fmt.Errorf("%v; повторное SSH-подключение: %w", err, dialErr)
				}
			}
			detail := redact(strs.LastLines(strings.TrimSpace(out+"\n"+errOut), 6))
			if err != nil && detail == "" {
				detail = redact(err.Error())
			}
			emit(Step{Name: name, OK: err == nil, Detail: detail})
			return detail, err
		}
		cmd := cleanupConfigBackupScript(backupDir)
		name := "cleanup conf backup"
		if !res.OK && activationAttempted {
			cmd = rollbackConfigScript(c.Interface, backupDir, digest, hadPrevious)
			name = "rollback conf"
		}
		detail, err := runRecovery(name, cmd)
		if err != nil {
			res.RollbackBackup = backupDir
			if activationAttempted && !res.OK {
				res.RollbackStatus = "failed"
				res.RollbackError = detail
				res.Error += "; откат не подтверждён, состояние VPS неизвестно; резервная копия: " + backupDir
			}
			return
		}
		if activationAttempted && !res.OK {
			res.Listening, res.Handshake = false, false
			if hadPrevious {
				res.RollbackStatus = "restored"
				res.Error += "; прежняя конфигурация VPS восстановлена и запущена"
			} else {
				res.RollbackStatus = "removed_new"
				res.Error += "; новая конфигурация удалена, ранее настроенного туннеля не было"
			}
			if _, err := runRecovery("cleanup conf backup", cleanupConfigBackupScript(backupDir)); err != nil {
				res.RollbackBackup = backupDir
			}
		}
	}()
	if err := r.Put(ctx, backupDir+"/new.conf", 0o600, config); err != nil {
		emit(Step{Name: "write conf", OK: false, Detail: "не удалось записать конфигурацию"})
		res.Error = "не удалось загрузить новую конфигурацию; активная конфигурация VPS не изменена"
		return res
	}
	activationAttempted = true // SSH may fail after the atomic rename already ran.
	if _, ok := step("activate conf", activateConfigScript(c.Interface, backupDir, digest, hadPrevious)); !ok {
		res.Error = "не удалось подтвердить замену конфигурации VPS"
		return res
	}
	emit(Step{Name: "write conf", OK: true, Detail: confPath})

	// 5. bring up (syncconf if already up, else enable the systemd unit)
	if _, ok := step("bring up", bringUpScript(c)); !ok {
		res.Error = "не удалось применить конфигурацию AmneziaWG (см. шаги)"
		return res
	}

	// 6. verify (interface up, listening, handshake best-effort)
	// `awg show` includes HeaderProtectionKey in some tool versions. Filter to
	// operational fields before collecting SSH output, in addition to redact().
	out, verifyOK := step("verify", fmt.Sprintf("set -e\nawg show %s 2>&1 | sed -n '/^interface:/p; /listening port:/p; /latest handshake:/p'; awg show %s listen-port >/dev/null; echo '==LISTEN=='; (ss -lun 2>/dev/null || netstat -lun 2>/dev/null) | grep ':%d' || echo none", c.Interface, c.Interface, c.ListenPort))
	res.Listening = strings.Contains(out, fmt.Sprintf(":%d", c.ListenPort))
	res.Handshake = strings.Contains(out, "latest handshake")
	res.OK = verifyOK && res.Listening
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

// The same reviewed dependency files are consumed by router release builds and
// embedded in the panel for VPS provisioning; no mutable remote lock is fetched.
//
//go:embed engine-deps.mod
var engineDependencyLock string

//go:embed engine-deps.sum
var engineDependencySums string

func engineDependencyVersion(module string) string {
	for _, line := range strings.Split(engineDependencyLock, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == module {
			return fields[1]
		}
	}
	panic("missing version in embedded AWG dependency lock: " + module)
}

// Check every linked dependency and the toolchain, not just the unchanged AWG
// protocol version: an older engine can have the same source revision but still
// carry vulnerable libraries. These exact versions come from the shared lock.
func userspaceEngineMetadataCheckScript() string {
	return fmt.Sprintf(`printf '%%s\n' "$metadata" | awk '
  /^[^\t]/ && $NF == "go%[1]s" { compiler=1 }
  $1 == "path" && $2 == "github.com/amnezia-vpn/amneziawg-go/v3" { module=1 }
  $1 == "build" && $2 == "vcs.revision=%[2]s" { revision=1 }
  $1 == "dep" && $2 == "golang.org/x/crypto" && $3 == "%[3]s" { crypto=1 }
  $1 == "dep" && $2 == "golang.org/x/net" && $3 == "%[4]s" { network=1 }
  $1 == "dep" && $2 == "golang.org/x/sys" && $3 == "%[5]s" { systemdep=1 }
  $1 == "=>" { replaced=1 }
  END { exit !(compiler && module && revision && crypto && network && systemdep && !replaced) }
'`, engineDependencyVersion("go"), AWGGoRevision,
		engineDependencyVersion("golang.org/x/crypto"), engineDependencyVersion("golang.org/x/net"), engineDependencyVersion("golang.org/x/sys"))
}

// userspaceInstallScript builds exact upstream tags with our dependency lock and
// verifies their Git revisions. Existing executables pass capability/version
// checks; amneziawg-go --version is not useful (3.1 still prints 0.0.20250522).
func userspaceInstallScript() string {
	return fmt.Sprintf(`set -eu
export DEBIAN_FRONTEND=noninteractive
export PATH=/usr/bin:/usr/sbin:/bin:/sbin
apt-get update -y
apt-get install -y iproute2 iptables curl ca-certificates git make build-essential pkg-config
work=$(mktemp -d /tmp/nfqws-awg.XXXXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
case "$(uname -m)" in
  x86_64) arch=amd64; checksum=d0f743b33e8d8945e6b1f432edd15785c70507121d6e2a723b21285eddf8b57b ;;
  aarch64|arm64) arch=arm64; checksum=211ffced9dcb9633a55eac6364816ec0ddd951389a740e88fa8b3337971bdda0 ;;
  *) echo 'Unsupported VPS architecture for pinned Go toolchain'; exit 1 ;;
esac
runtime=/usr/local/lib/nfqws-awg/go%[8]s
if ! "$runtime/bin/go" version 2>/dev/null | grep -Fq 'go%[8]s '; then
  curl --proto '=https' --tlsv1.2 -fsSL "https://go.dev/dl/go%[8]s.linux-$arch.tar.gz" -o "$work/go.tar.gz"
  printf '%%s  %%s\n' "$checksum" "$work/go.tar.gz" | sha256sum -c -
  mkdir -p "$runtime"
  tar -xzf "$work/go.tar.gz" --strip-components=1 -C "$runtime"
fi
if ! awg --version 2>/dev/null | grep -Fq '%[1]s'; then
  git clone --depth 1 --branch '%[1]s' https://github.com/amnezia-vpn/amneziawg-tools "$work/tools"
  [ "$(git -C "$work/tools" rev-parse HEAD)" = '%[2]s' ]
  make -C "$work/tools/src" WITH_WGQUICK=yes WITH_SYSTEMDUNITS=yes
  make -C "$work/tools/src" WITH_WGQUICK=yes WITH_SYSTEMDUNITS=yes PREFIX=/usr install
fi
engine_current() {
  metadata=$("$runtime/bin/go" version -m "$1" 2>/dev/null) || return 1
%[7]s
}
if ! engine_current /usr/bin/amneziawg-go; then
  git clone --depth 1 --branch '%[3]s' https://github.com/amnezia-vpn/amneziawg-go "$work/engine"
  [ "$(git -C "$work/engine" rev-parse HEAD)" = '%[4]s' ]
  cat > "$work/engine-deps.mod" <<'NFQWS_AWG_MOD'
%[5]sNFQWS_AWG_MOD
  cat > "$work/engine-deps.sum" <<'NFQWS_AWG_SUM'
%[6]sNFQWS_AWG_SUM
  (cd "$work/engine" && GOTOOLCHAIN=local CGO_ENABLED=0 "$runtime/bin/go" build -modfile="$work/engine-deps.mod" -mod=readonly -buildvcs=true -trimpath -ldflags '-s -w' -o "$work/amneziawg-go" .)
  engine_current "$work/amneziawg-go"
  install -m755 "$work/amneziawg-go" /usr/bin/amneziawg-go
fi
engine_current /usr/bin/amneziawg-go
awg --version | grep -F '%[1]s'
test -x /usr/bin/awg-quick
mkdir -p /usr/local/libexec
# Keep upstream quick configuration/NAT behavior; only interface creation is
# forced to userspace so a loaded older kernel module cannot claim the tunnel.
awk '
  /^add_if\(\) \{$/ { print "add_if() {"; print "\tcmd /usr/bin/amneziawg-go \"$INTERFACE\""; print "}"; skip=1; next }
  skip && /^\}$/ { skip=0; next }
  !skip { print }
' /usr/bin/awg-quick > "$work/awg-quick-userspace"
grep -Fq 'cmd /usr/bin/amneziawg-go' "$work/awg-quick-userspace"
install -m755 "$work/awg-quick-userspace" /usr/local/libexec/nfqws-awg-quick-userspace
echo 'userspace %[3]s ready'`, AWGToolsVersion, AWGToolsRevision, AWGGoVersion, AWGGoRevision,
		engineDependencyLock, engineDependencySums, userspaceEngineMetadataCheckScript(), engineDependencyVersion("go"))
}

func userspaceServiceScript(iface string) string {
	if iface == "" {
		iface = "awg0"
	}
	return fmt.Sprintf(`set -eu
mkdir -p /etc/systemd/system/awg-quick@%[1]s.service.d
cat > /etc/systemd/system/awg-quick@%[1]s.service.d/10-nfqws-userspace.conf <<'AWGUNIT'
[Service]
ExecStart=
ExecStart=/usr/local/libexec/nfqws-awg-quick-userspace up %%i
ExecStop=
ExecStop=/usr/local/libexec/nfqws-awg-quick-userspace down %%i
AWGUNIT
systemctl daemon-reload`, iface)
}

func bringUpScript(c *ServerConfig) string {
	iface := strings.TrimSpace(c.Interface)
	if iface == "" {
		iface = "awg0"
	}
	if c.RequiresAWG31() || c.TrafficObfuscation != nil || c.Install == "userspace" {
		// Device-level parameters omitted by syncconf retain their old values.
		// Restart is mandatory for switching obfuscation off or replacing 3.1.
		return fmt.Sprintf(`set -eu
systemctl enable awg-quick@%[1]s
systemctl stop awg-quick@%[1]s || true
if ip link show %[1]s >/dev/null 2>&1; then awg-quick down %[1]s; fi
systemctl start awg-quick@%[1]s
%[2]s
echo bring-up-done`, iface, serverPostUpCommands(c.Subnet, c.WANIface, iface))
	}
	return fmt.Sprintf(`systemctl enable awg-quick@%[1]s >/dev/null 2>&1 || true
if ip link show %[1]s >/dev/null 2>&1; then
  awg-quick strip %[1]s > /tmp/awg-%[1]s.sync 2>/dev/null && awg syncconf %[1]s /tmp/awg-%[1]s.sync 2>&1
  rc=$?
  rm -f /tmp/awg-%[1]s.sync
  [ "$rc" -eq 0 ] || exit "$rc"
else
  (systemctl start awg-quick@%[1]s 2>&1 || awg-quick up %[1]s 2>&1) || exit 1
fi
%[2]s
echo bring-up-done`, iface, serverPostUpCommands(c.Subnet, c.WANIface, iface))
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
