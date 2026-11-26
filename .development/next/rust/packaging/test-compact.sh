#!/bin/sh
# Exercise package selection and failure handling in an isolated directory.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/n2s-compact-test.XXXXXX")
trap 'rm -rf "$tmp"' 0
sed -n '/^compact_inventory() {/,/^}/p; /^compact_packages() {/,/^}/p; /^stage_compact() {/,/^}/p; /^retire_compact_snapshot() (/,/^)/p; /^panel_inode() {/,/^}/p; /^snapshot_compact() {/,/^}/p; /^restore_compact() {/,/^}/p; /^cleanup_accepted_install() {/,/^}/p; /^cleanup_stage() {/,/^}/p' "$script_dir/install.sh" > "$tmp/functions"
sed -n '/^remove_compact_packages() {/,/^}/p' "$script_dir/uninstall.sh" >> "$tmp/functions"
. "$tmp/functions"
say() { :; }
active_profile=full
PM=opkg
COMPACT_BIN=$tmp/lib/n2s-compact
mkdir "$tmp/lib"
cp "$(command -v sh)" "$COMPACT_BIN"
ln() {
  # Capture the requested link without requiring host symlink privileges.
  [ "$#" = 3 ] && [ "$1" = -s ] && [ "$2" = "$COMPACT_BIN" ] || return 1
  printf '%s\n' "$2" > "$3"
}
opkg() {
  case "$1" in
    list-installed) cat "$tmp/installed" ;;
    install)
      shift
      [ "$N2S_INSTALLING_COMPACT" = 1 ] || return 1
      printf '%s\n' "$@" > "$tmp/transaction"
      cat "$tmp/upgrade" > "$tmp/installed"
      ;;
    *) return 1 ;;
  esac
}
printf 'other-package - 9\n' > "$tmp/installed"
printf 'nfqws2-strategy-compact - 2\n' > "$tmp/upgrade"
stage_compact "$tmp/core"
[ "$(cat "$tmp/transaction")" = nfqws2-strategy-compact ]
[ "$(cat "$tmp/core")" = "$COMPACT_BIN" ]
if N2S_EXPECT_PACKAGE_VERSION=3 stage_compact "$tmp/wrong-version"; then exit 1; fi
[ ! -e "$tmp/wrong-version" ]
N2S_EXPECT_PACKAGE_VERSION=2 stage_compact "$tmp/exact-version"

cat >> "$tmp/installed" <<'EOF'
nfqws2-strategy-runs - 1
nfqws2-strategy-geo - 1
nfqws2-strategy-trace - 1
nfqws2-strategy-tgws - 1
nfqws2-strategy-tools - 1
nfqws2-strategy-unrelated - 1
EOF
cat >> "$tmp/upgrade" <<'EOF'
nfqws2-strategy-runs - 2
nfqws2-strategy-geo - 2
nfqws2-strategy-trace - 2
nfqws2-strategy-tgws - 2
nfqws2-strategy-tools - 2
EOF
stage_compact "$tmp/updated"
printf 'nfqws2-strategy-compact\nnfqws2-strategy-runs\nnfqws2-strategy-geo\nnfqws2-strategy-trace\nnfqws2-strategy-tgws\nnfqws2-strategy-tools\n' > "$tmp/expected"
cmp "$tmp/expected" "$tmp/transaction"
[ "$(cat "$tmp/updated")" = "$COMPACT_BIN" ]

sed 's/nfqws2-strategy-runs - 2/nfqws2-strategy-runs - 1/' "$tmp/installed" > "$tmp/upgrade"
if stage_compact "$tmp/mixed"; then echo 'accepted mixed package versions' >&2; exit 1; fi
[ ! -e "$tmp/mixed" ]
opkg() { return 1; }
if stage_compact "$tmp/failed"; then echo 'ignored opkg failure' >&2; exit 1; fi
[ ! -e "$tmp/failed" ]

# Both Go builds used the in-process Telegram and trace workers. The full
# build also exposed each page which now has its own compact package.
(
  go_source=1
  stage=$tmp/go-stage
  COMPACT_BIN=$tmp/go-compact/n2s-compact
  mkdir -p "$stage" "${COMPACT_BIN%/*}"
  cat > "$stage/candidate" <<'SH'
#!/bin/sh
[ "$1/$2" = 'prepare-go-routing/--supported' ] && echo go-routing-v1
SH
  chmod 700 "$stage/candidate"
  opkg() {
    case "$1" in
      list-installed) cat "$stage/installed" ;;
      list-upgradable) printf 'nfqws2-strategy-compact - 1 - 2\n' ;;
      install)
        shift
        [ "$N2S_INSTALLING_COMPACT" = 1 ] || return 1
        printf '%s\n' "$*" >> "$stage/actions"
        if [ "$1" = nfqws2-strategy-compact ]; then
          cp -p "$stage/candidate" "$COMPACT_BIN" || return 1
          : > "$stage/installed"
        fi
        for pkg do printf '%s - 2\n' "$pkg" >> "$stage/installed"; done ;;
      *) return 1 ;;
    esac
  }
  : > "$stage/installed"
  stage_compact "$stage/full"
  grep -qx 'nfqws2-strategy-runs nfqws2-strategy-blockcheck nfqws2-strategy-strategies nfqws2-strategy-geo nfqws2-strategy-trace nfqws2-strategy-tgws' "$stage/actions"
  active_profile=compact
  printf 'Go compact payload\n' > "$COMPACT_BIN"
  printf 'nfqws2-strategy-compact - 1\nnfqws2-strategy-geo - 1\n' > "$stage/installed"
  : > "$stage/actions"
  stage_compact "$stage/compact"
  grep -qx 'nfqws2-strategy-compact nfqws2-strategy-geo' "$stage/actions"
  grep -qx 'nfqws2-strategy-trace nfqws2-strategy-tgws' "$stage/actions"
  grep -qx nfqws2-strategy-tgws "$repair_file"
  [ "$(cat "$compact_backup/n2s-compact")" = 'Go compact payload' ]
)

# Simulate an opkg process that truncates core/catalog and advances its DB,
# then fails. Retry must repair a missing formerly selected package as well.
active_profile=compact
stage=$tmp/stage
mkdir -p "$stage" "$tmp/lib/modules/strategies"
for module in runs trace blockcheck strategies tgws; do
  mkdir -p "$tmp/lib/modules/$module"
  printf 'previous helper\n' > "$tmp/lib/modules/$module/nfqws2-$module"
done
catalog=$tmp/lib/modules/strategies/catalog.json
extra=$tmp/lib/modules/strategies/strategies-newhash.js.gz
unrelated=$tmp/lib/modules/strategies/user-notes.txt
printf 'user file\n' > "$unrelated"
printf 'previous catalog\n' > "$catalog"
previous=$(wc -c < "$COMPACT_BIN")
printf 'nfqws2-strategy-compact - 1\nnfqws2-strategy-strategies - 1\n' > "$tmp/installed"
opkg() {
  case "$1" in
    list-installed) cat "$tmp/installed" ;;
    list-upgradable) printf 'nfqws2-strategy-compact - 1 - 2\n' ;;
    install)
      printf 'bad\n' > "$COMPACT_BIN"
      printf 'bad\n' > "$catalog"
      printf 'new page\n' > "$extra"
      for module in runs trace blockcheck strategies tgws; do
        printf 'bad\n' > "$tmp/lib/modules/$module/nfqws2-$module"
      done
      printf 'nfqws2-strategy-compact - 2\n' > "$tmp/installed"
      return 1 ;;
    --force-reinstall)
      [ "$2 $3 $4" = 'install nfqws2-strategy-compact nfqws2-strategy-strategies' ] || return 1
      printf 'new catalog\n' > "$catalog"
      printf 'nfqws2-strategy-strategies - 2\n' >> "$tmp/installed" ;;
    *) return 1 ;;
  esac
}
if stage_compact "$tmp/broken"; then echo 'ignored partial opkg failure' >&2; exit 1; fi
[ "$rollback_compact" = 1 ] && [ -f "$repair_file" ]
was_running=0
fail_once=1
mv() {
  if [ "$fail_once" = 1 ] && [ "${3:-}" = "$catalog" ]; then fail_once=0; return 1; fi
  command mv "$@"
}
if restore_compact; then echo 'ignored partial restore failure' >&2; exit 1; fi
[ -f "$compact_backup/n2s-compact" ] && [ -f "$compact_backup/modules/strategies/catalog.json" ]
cleanup_stage
[ "$(wc -c < "$COMPACT_BIN")" = "$previous" ]
[ "$(cat "$catalog")" = 'previous catalog' ]
[ ! -e "$extra" ] && [ "$(cat "$unrelated")" = 'user file' ]
for module in runs trace blockcheck strategies tgws; do
  [ "$(cat "$tmp/lib/modules/$module/nfqws2-$module")" = 'previous helper' ]
done
stage=$tmp/retry
mkdir "$stage"
rollback_compact=0
stage_compact "$tmp/repaired"
[ "$rollback_compact" = 1 ] && [ "$(cat "$tmp/repaired")" = "$COMPACT_BIN" ]
[ "$(cat "$catalog")" = 'new catalog' ]
# The new package set validated but its service failed the startup check.
# The EXIT handler restores files before restarting the previous service.
INIT=mock_init
was_running=1
mock_init() {
  case "$1" in
    status) printf 'stopped\n' ;;
    start)
      [ "$(cat "$catalog")" = 'previous catalog' ] || return 1
      printf 'restarted\n' > "$tmp/service" ;;
    *) return 1 ;;
  esac
}
cleanup_stage
[ "$(cat "$tmp/service")" = restarted ] && [ -f "$repair_file" ]
[ ! -e "$compact_backup" ]

# Two failed transactions with an interrupted rollback between them. The
# package writer truncates existing payloads, including a restored module.
(
  unset -f ln
  compact_dir=$tmp/repeated-failure
  COMPACT_BIN=$compact_dir/n2s-compact
  stage=$tmp/first-attempt
  geo=$compact_dir/modules/geo/nfqws2-geo
  catalog=$compact_dir/modules/strategies/catalog.json
  tgws=$compact_dir/modules/tgws/nfqws2-tgws
  mkdir -p "$stage" "${geo%/*}" "${catalog%/*}" "${tgws%/*}"
  printf 'original panel\n' > "$COMPACT_BIN"
  printf 'original worker\n' > "$geo"
  printf 'original catalog\n' > "$catalog"
  printf 'my settings\n' > "$compact_dir/user-settings"
  was_running=0 rollback_compact=0 snapshot_started=0
  opkg() {
    case "$1" in
      list-installed) printf '%s - 1\n' nfqws2-strategy-compact nfqws2-strategy-geo nfqws2-strategy-strategies ;;
      list-upgradable) echo 'nfqws2-strategy-compact - 1 - 2' ;;
      install|--force-reinstall)
        echo "$1" >> "$compact_dir/attempts"
        echo 'partial panel' > "$COMPACT_BIN"
        echo 'partial worker' > "$geo"
        echo 'partial catalog' > "$catalog"
        echo 'unexpected worker' > "$tgws"
        return 1 ;;
      *) return 1 ;;
    esac
  }
  if stage_compact "$stage/n2s"; then exit 1; fi
  mv() {
    [ "${3:-}" != "$catalog" ] || return 1
    command mv "$@"
  }
  if cleanup_stage; then echo 'ignored interrupted payload restoration' >&2; exit 1; fi
  [ "$(cat "$geo")" = 'original worker' ] && [ -f "$compact_backup/.ready" ] || exit 1
  unset -f mv
  stage=$tmp/second-attempt
  mkdir "$stage"
  rollback_compact=0 snapshot_started=0
  if [ "$geo" -ef "$compact_backup/modules/geo/nfqws2-geo" ]; then
    cp() {
      [ "${3:-}" != "$compact_backup/.detaching" ] || return 1
      command cp "$@"
    }
    if stage_compact "$stage/n2s"; then exit 1; fi
    [ "$(cat "$compact_dir/attempts")" = install ] && [ "$rollback_compact" = 0 ] || exit 1
    unset -f cp
  fi
  if stage_compact "$stage/n2s"; then exit 1; fi
  cleanup_stage
  [ "$(cat "$compact_dir/attempts")" = "$(printf 'install\n--force-reinstall')" ] &&
    [ "$(cat "$COMPACT_BIN")" = 'original panel' ] && [ "$(cat "$geo")" = 'original worker' ] &&
    [ "$(cat "$catalog")" = 'original catalog' ] && [ ! -e "$tgws" ] &&
    [ "$(cat "$compact_dir/user-settings")" = 'my settings' ] ||
    { echo 'a second package failure overwrote the retained rollback snapshot' >&2; exit 1; }
)
echo 'Compact repair after two failed package writes and an interrupted restore: passed'

# A cleanup failure after successful Go handoff must leave the confirmed
# Rust executable and its matching modules installed. Exercise real errexit
# and the installer's EXIT trap in a separate shell.
awk '/^verify_go_services "\$handoff_endpoint"/ {emit=1}
  /^if \[ "\$active_profile" = compact \] \&\& \[ "\$profile" = full \]/ {emit=0}
  emit' "$script_dir/install.sh" > "$tmp/accept"
cat > "$tmp/postcommit" <<'SH'
set -eu
tmp=$1 mode=$2 fail=$3
. "$tmp/functions"
compact_dir=$tmp/accepted-$mode-$fail
COMPACT_BIN=$compact_dir/n2s-compact repair_file=$compact_dir/.compact-repair
stage=$compact_dir/stage
profile=compact active_profile=compact rollback_compact=0 snapshot_started=0
rollback_go=1 go_preparing=1 go_trial=$mode was_running=0
DATA=$compact_dir/data BIN=finish_native handoff_endpoint=8090
selected=nfqws2-strategy-geo
mkdir -p "$compact_dir/modules/geo" "$compact_dir/modules/tgws" "$stage" "$DATA/.store/runtime"
echo go > "$COMPACT_BIN"
echo go-module > "$compact_dir/modules/geo/nfqws2-geo"
echo removed-module > "$compact_dir/modules/tgws/nfqws2-tgws"
snapshot_compact
echo rust > "$COMPACT_BIN"
echo rust-module > "$compact_dir/modules/geo/nfqws2-geo"
rm "$compact_dir/modules/tgws/nfqws2-tgws"
echo user-data > "$DATA/settings"
echo checkpoint > "$DATA/.store/runtime/awg-go-release.json"
touch "$compact_dir/inject"
say() { :; }
die() { exit 1; }
verify_go_services() { touch "$compact_dir/verified"; }
finish_native() { [ "$1" = finish-go-routing ] && touch "$compact_dir/committed"; }
rm() {
  case "$fail/${2:-}" in
    "persistent/$compact_dir/.compact-previous") return 1 ;;
    "ready/$compact_dir/.compact-previous/.ready") touch "$compact_dir/blocked-ready"; return 1 ;;
    "receipt/$repair_file"|"journal/$DATA/.store/runtime/awg-go-release.json")
      if [ -f "$compact_dir/inject" ]; then command rm "$compact_dir/inject"; return 1; fi ;;
  esac
  command rm "$@"
}
trap cleanup_stage 0
. "$tmp/accept"
SH
for mode in inactive trial; do
  case "$mode" in inactive) fail=receipt ;; trial) fail=journal ;; esac
  sh "$tmp/postcommit" "$tmp" "$mode" "$fail"
  dest=$tmp/accepted-$mode-$fail
  [ -e "$dest/verified" ] && [ ! -e "$dest/inject" ] || exit 1
  [ "$mode" = inactive ] || [ -f "$dest/committed" ] || exit 1
  [ "$(cat "$dest/n2s-compact")" = rust ] && [ "$(cat "$dest/modules/geo/nfqws2-geo")" = rust-module ] ||
    { echo 'restored Go package files after accepting the new Rust service' >&2; exit 1; }
  [ "$(cat "$dest/data/settings")" = user-data ] && [ ! -e "$dest/.compact-previous" ] || exit 1
  [ ! -e "$dest/.compact-repair" ] && [ ! -e "$dest/stage" ] || exit 1
done
check_accepted_retry() (
  fail=$1
  if sh "$tmp/postcommit" "$tmp" inactive "$fail"; then echo 'hid persistent cleanup failure' >&2; exit 1; fi
  compact_dir=$tmp/accepted-inactive-$fail
  COMPACT_BIN=$compact_dir/n2s-compact repair_file=$compact_dir/.compact-repair
  stage=$compact_dir/retry selected=nfqws2-strategy-geo
  mkdir "$stage"
  [ -f "$repair_file" ] && [ ! -e "$compact_dir/stage" ] && [ "$(cat "$COMPACT_BIN")" = rust ] || exit 1
  case "$fail" in
    ready)
      [ -f "$compact_dir/blocked-ready" ] && [ -f "$compact_dir/.compact-previous/.ready" ] || exit 1
      rollback_compact=0
      rm() {
        [ "${2:-}" != "$compact_dir/.compact-previous" ] || return 1
        command rm "$@"
      }
      if snapshot_compact; then echo 'armed rollback from a retired snapshot' >&2; exit 1; fi
      unset -f rm
      [ "$rollback_compact" = 0 ] && [ -f "$compact_dir/.compact-accepted-snapshot" ] || exit 1
      mv "$compact_dir/.compact-previous" "$compact_dir/original-backup"
      mkdir "$compact_dir/.compact-previous"
      touch "$compact_dir/.compact-previous/foreign"
      if snapshot_compact; then echo 'accepted a replacement snapshot directory' >&2; exit 1; fi
      [ -f "$compact_dir/.compact-previous/foreign" ] || exit 1
      mv "$compact_dir/.compact-previous" "$compact_dir/foreign-backup"
      mv "$compact_dir/original-backup" "$compact_dir/.compact-previous"
      ;;
    persistent) [ ! -f "$compact_dir/.compact-previous/.ready" ] || exit 1 ;;
  esac
  snapshot_compact
  [ ! -e "$compact_dir/.compact-accepted-snapshot" ] || exit 1
  echo failed-retry > "$COMPACT_BIN"
  echo partial-module > "$compact_dir/modules/geo/nfqws2-geo"
  restore_compact
  [ "$(cat "$COMPACT_BIN")" = rust ] && [ "$(cat "$compact_dir/modules/geo/nfqws2-geo")" = rust-module ] &&
    [ ! -e "$compact_dir/modules/tgws/nfqws2-tgws" ] && [ "$(cat "$compact_dir/data/settings")" = user-data ] ||
    { echo 'failed retry restored a retired Go package snapshot' >&2; exit 1; }
)
check_accepted_retry persistent
check_accepted_retry ready
echo 'Confirmed Rust service survives postcommit errors, disabled modules and the next rollback: passed'

# A failed package operation may replace an alias with a regular file or
# remove the common executable. A snapshot stores a single copy of the ELF.
compact_dir=$tmp/shared
COMPACT_BIN=$compact_dir/n2s-compact
stage=$tmp/shared-stage
repair_file=$compact_dir/.compact-repair
selected='nfqws2-strategy-geo nfqws2-strategy-tools'
mkdir -p "$stage" "$compact_dir/modules/geo" "$compact_dir/modules/tools"
cp -p "$(command -v sh)" "$COMPACT_BIN"
tools="$compact_dir/modules/tools/nfqws2-tools"
alias_path="$compact_dir/modules/geo/nfqws2-geo"
printf 'shared executable\n' > "$tools"
if command ln -s ../tools/nfqws2-tools "$alias_path" && [ -L "$alias_path" ]; then
  snapshot_compact
  [ -L "$compact_backup/modules/geo/nfqws2-geo" ]
  [ "$(cat "$compact_backup/modules/tools/nfqws2-tools")" = 'shared executable' ]
  rm -f "$alias_path" "$tools"
  printf 'partial upgrade\n' > "$alias_path"
  restore_compact
  [ "$(readlink "$alias_path")" = '../tools/nfqws2-tools' ]
  [ "$(cat "$alias_path")" = 'shared executable' ]
else
  case "$(uname -s)" in MSYS*|MINGW*) : ;; *) echo 'failed to create fixture symlink' >&2; exit 1 ;; esac
fi
echo 'compact install, selected upgrades and rollback/retry: passed'

# apk prints "name-version architecture ... [installed]" and upgrades only
# installed modules. Test changing a partially installed set before repair.
PM=apk
active_profile=full
compact_dir=$tmp/apk
COMPACT_BIN=$compact_dir/n2s-compact
stage=$tmp/apk-stage
mkdir -p "$compact_dir" "$stage"
cp -p "$(command -v sh)" "$COMPACT_BIN"
cat > "$tmp/apk-current" <<'EOF'
nfqws2-strategy-compact-1.8.3-r1 mipsel_24kc {nfqws2-strategy} (MIT) [installed]
nfqws2-strategy-geo-1.8.3-r1 mipsel_24kc {nfqws2-strategy} (MIT) [installed]
nfqws2-strategy-tools-1.8.3-r1 mipsel_24kc {nfqws2-strategy} (MIT) [installed]
nfqws2-strategy-foreign-1.8.3-r1 mipsel_24kc {other} (MIT) [installed]
EOF
sed s/1.8.3-r1/1.8.3-r2/g "$tmp/apk-current" > "$tmp/apk-latest"
: > "$tmp/apk-upgradable"
apk() {
  case "$1 $2" in
    'list --installed') [ "$3" = 'nfqws2-strategy-*' ] && cat "$tmp/apk-current" ;;
    'list --upgradable') [ "$3" = 'nfqws2-strategy-*' ] && cat "$tmp/apk-upgradable" ;;
    'add '*|'upgrade '*|'fix '*)
      [ "$N2S_INSTALLING_COMPACT" = 1 ] || return 1
      printf '%s\n' "$*" >> "$tmp/apk-actions"
      cp "$tmp/apk-latest" "$tmp/apk-current" ;;
    'del '*) printf '%s\n' "$*" >> "$tmp/apk-actions" ;;
    *) return 1 ;;
  esac
}
compact_apk() { N2S_INSTALLING_COMPACT=1 apk "$@"; }
stage_compact "$stage/core"
grep -qx 'add nfqws2-strategy-compact' "$tmp/apk-actions"
active_profile=compact
: > "$tmp/apk-actions"
stage_compact "$stage/current"
[ ! -s "$tmp/apk-actions" ] && [ ! -e "$compact_dir/.compact-previous" ]
cp "$tmp/apk-latest" "$tmp/apk-upgradable"
stage_compact "$stage/upgraded"
grep -qx 'upgrade nfqws2-strategy-compact nfqws2-strategy-geo nfqws2-strategy-tools' "$tmp/apk-actions"
[ -f "$repair_file" ]
sed -n '/^nfqws2-strategy-compact-/p' "$tmp/apk-latest" > "$tmp/apk-current"
stage_compact "$stage/repaired"
grep -qx 'add --upgrade nfqws2-strategy-compact nfqws2-strategy-geo' "$tmp/apk-actions"
grep -qx 'fix --reinstall nfqws2-strategy-compact nfqws2-strategy-geo nfqws2-strategy-tools' "$tmp/apk-actions"
compact_modules='nfqws2-strategy-geo'
compact_installed=$(compact_inventory installed)
remove_compact_packages
grep -qx 'del nfqws2-strategy-geo nfqws2-strategy-tools nfqws2-strategy-compact' "$tmp/apk-actions"
PM=opkg
opkg() { printf '%s\n' "$*" >> "$tmp/opkg-remove"; }
remove_compact_packages
[ "$(cat "$tmp/opkg-remove")" = "$(printf 'remove nfqws2-strategy-geo\nremove nfqws2-strategy-tools\nremove nfqws2-strategy-compact')" ]
echo 'OpenWrt opkg/apk module selection, no-op update, repair and removal: passed'

# Exercise the generated service with procd's argument-oriented API.
INIT=$tmp/nfqws2-strategy
BIN=/usr/bin/n2s
DATA=/etc/nfqws2-strategy
LOG_DIR=/var/log
PORT=8123
COMPACT_BIN=/usr/lib/nfqws2-strategy/n2s-compact
awk '/^  cat > "\$INIT" <<EOF$/ {emit=1} emit {print; if ($0 == "EOF") exit}' "$script_dir/install.sh" > "$tmp/render-init"
. "$tmp/render-init"
. "$INIT"
procd_open_instance() { :; }
procd_set_param() { key=$1; shift; printf '%s\n' "$@" > "$tmp/procd-$key"; }
procd_close_instance() { :; }
start_service
[ "$(cat "$tmp/procd-command")" = "$(printf '%s\n' /usr/bin/n2s serve -l :8123 -log /var/log/nfqws2-strategy.log)" ]
grep -qx 'N2S_MODULE_DIR=/usr/lib/nfqws2-strategy/modules' "$tmp/procd-env"
grep -qx 'N2S_DATA=/etc/nfqws2-strategy' "$tmp/procd-env"
echo 'OpenWrt procd foreground command, selected port and module directory: passed'
