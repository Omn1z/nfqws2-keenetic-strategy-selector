set -eu
export DEBIAN_FRONTEND=noninteractive
export PATH=/usr/bin:/usr/sbin:/bin:/sbin
apt-get update -y
apt-get install -y iproute2 iptables curl ca-certificates git make build-essential pkg-config
work=$(mktemp -d /tmp/nfqws-awg.XXXXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
case "$(uname -m)" in
  x86_64) arch=amd64; checksum=9849f4e04ee35303714e34fbc3ac8ab44ea3e448a95aa182f91e3b9b79c710ec ;;
  aarch64|arm64) arch=arm64; checksum=6c2f29b458b5add0835f18b776f69c8881a6d88428f1484a6da55755e620757e ;;
  *) echo 'Unsupported VPS architecture for pinned Go toolchain'; exit 1 ;;
esac
runtime=/usr/local/lib/nfqws-awg/go@GO_VERSION@
if ! "$runtime/bin/go" version 2>/dev/null | grep -Fq 'go@GO_VERSION@ '; then
  curl --proto '=https' --tlsv1.2 -fsSL "https://go.dev/dl/go@GO_VERSION@.linux-$arch.tar.gz" -o "$work/go.tar.gz"
  printf '%s  %s\n' "$checksum" "$work/go.tar.gz" | sha256sum -c -
  mkdir -p "$runtime"
  tar -xzf "$work/go.tar.gz" --strip-components=1 -C "$runtime"
fi
if ! awg --version 2>/dev/null | grep -Fq '@TOOLS_VERSION@'; then
  git clone --depth 1 --branch '@TOOLS_VERSION@' https://github.com/amnezia-vpn/amneziawg-tools "$work/tools"
  [ "$(git -C "$work/tools" rev-parse HEAD)" = '@TOOLS_REV@' ]
  make -C "$work/tools/src" WITH_WGQUICK=yes WITH_SYSTEMDUNITS=yes
  make -C "$work/tools/src" WITH_WGQUICK=yes WITH_SYSTEMDUNITS=yes PREFIX=/usr install
fi
engine_current() {
  metadata=$("$runtime/bin/go" version -m "$1" 2>/dev/null) || return 1
@METADATA_CHECK@
}
if ! engine_current /usr/bin/amneziawg-go; then
  git clone --depth 1 --branch '@ENGINE_VERSION@' https://github.com/amnezia-vpn/amneziawg-go "$work/engine"
  [ "$(git -C "$work/engine" rev-parse HEAD)" = '@ENGINE_REV@' ]
  cat > "$work/engine-deps.mod" <<'NFQWS_AWG_MOD'
@DEPS_MOD@NFQWS_AWG_MOD
  cat > "$work/engine-deps.sum" <<'NFQWS_AWG_SUM'
@DEPS_SUM@NFQWS_AWG_SUM
  (cd "$work/engine" && GOTOOLCHAIN=local CGO_ENABLED=0 "$runtime/bin/go" build -modfile="$work/engine-deps.mod" -mod=readonly -buildvcs=true -trimpath -ldflags '-s -w' -o "$work/amneziawg-go" .)
  engine_current "$work/amneziawg-go"
  install -m755 "$work/amneziawg-go" /usr/bin/amneziawg-go
fi
engine_current /usr/bin/amneziawg-go
awg --version | grep -F '@TOOLS_VERSION@'
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
echo 'userspace @ENGINE_VERSION@ ready'
