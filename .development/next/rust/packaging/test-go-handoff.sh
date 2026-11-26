#!/bin/sh
# Exercise the Keenetic installer's PID validation and rollback paths without
# sending signals or touching router data.
set -eu
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/n2s-go-handoff.XXXXXX")
trap 'rm -rf "$tmp"' 0
src=$script_dir/install.sh
sed -n '/^read_selective_init() {/,/^}/p' "$src" > "$tmp/init-pref"
. "$tmp/init-pref"
printf '%s\n' '#export N2S_AWG_SELECTIVE_ACCEL=1' 'export N2S_AWG_SELECTIVE_ACCEL=9' > "$tmp/old-init"
[ -z "$(read_selective_init "$tmp/old-init")" ]
echo '  export N2S_AWG_SELECTIVE_ACCEL=1 ' >> "$tmp/old-init"
[ "$(read_selective_init "$tmp/old-init")" = 1 ]
echo 'export N2S_AWG_SELECTIVE_ACCEL=0' >> "$tmp/old-init"
[ "$(read_selective_init "$tmp/old-init")" = 0 ]
RUN_DIR=$tmp/run
mkdir -p "$RUN_DIR" "$tmp/proc/72"
sed -n '/^panel_inode() {/,/^}/p; /^panel_token() (/,/^)/p; /^find_panel() (/,/^)/p; /^go_listen_options() (/,/^)/p; /^resolve_handoff_ports() {/,/^}/p; /^valid_bind_host() {/,/^}/p' "$src" |
  sed "s#/proc/#$tmp/proc/#g" > "$tmp/process-functions"
. "$tmp/process-functions"
procdir=$tmp/proc/72
printf 'binary\n' > "$procdir/exe"
inode=$(panel_inode "$procdir/exe")
printf '%s\000' /opt/usr/bin/n2s serve -d -pid "$RUN_DIR/nfqws2-strategy.pid" > "$procdir/cmdline"
printf '72 (name ) with spaces) S' > "$procdir/stat"
i=1
while [ "$i" -le 18 ]; do printf ' 0' >> "$procdir/stat"; i=$((i+1)); done
printf ' 98765\n' >> "$procdir/stat"
[ "$(find_panel "$inode")" = 72/98765 ]
[ "$(go_listen_options "$procdir")" = saved/:8090 ]
printf '%s\000' N2S_LISTEN=127.0.0.1:9010 > "$procdir/environ"
[ "$(go_listen_options "$procdir")" = saved/127.0.0.1:9010 ]
printf '%s\000' /opt/usr/bin/n2s serve -log --ignore-saved-port -l '[::]:9079' -pid "$RUN_DIR/nfqws2-strategy.pid" > "$procdir/cmdline"
[ "$(go_listen_options "$procdir")" = 'saved/[::]:9079' ]
printf '%s\000' --ignore-saved-port >> "$procdir/cmdline"
[ "$(go_listen_options "$procdir")" = 'explicit/[::]:9079' ]
[ -z "$(find_panel 999:888)" ]
printf '%s\000' /opt/usr/bin/n2s serve -pid "$RUN_DIR/other.pid" > "$procdir/cmdline"
[ -z "$(find_panel "$inode")" ]
printf '%s\000' /opt/usr/bin/n2s config > "$procdir/cmdline"
[ -z "$(find_panel "$inode")" ]

(
  sed -n '/^wait_panel_exit() (/,/^)/p' "$src" > "$tmp/wait-panel-exit"
  . "$tmp/wait-panel-exit"
  panel_token() {
    [ "$1/$2" = "72/98765" ] && [ ! -f "$tmp/exited" ] && echo 72/123
  }
  sleep() {
    if [ "$1" = 0.0 ]; then [ "$interval_supported" = yes ]; return; fi
    printf '%s\n' "$1" > "$tmp/poll-interval"
    touch "$tmp/exited"
  }
  for interval_supported in yes no; do
    rm -f "$tmp/exited"
    wait_panel_exit 72/123 98765
    if [ "$interval_supported" = yes ]; then expected=0.1; else expected=1; fi
    [ "$(cat "$tmp/poll-interval")" = "$expected" ]
  done
)

(
  sed -n '/^prepare_go_data_snapshot() {/,/^}/p; /^save_go_data_snapshot() {/,/^}/p' "$src" > "$tmp/data-snapshot"
  . "$tmp/data-snapshot"
  stage=$tmp/snapshot-stage
  go_data_path=$tmp/panel-data
  DATA=$tmp/panel-data-link
  mkdir "$stage" "$go_data_path"
  ln -s "$go_data_path" "$DATA"
  printf 'settings while Go is running\n' > "$DATA/config"
  prepare_go_data_snapshot
  [ "$(cat "$stage/data-location")" = "$go_data_stage" ]
  [ ! -e "$go_data_stage/original" ]
  printf 'final settings from Go\n' > "$DATA/config"
  mv "$go_data_path" "$tmp/detached-data"
  mkdir "$go_data_path"
  if save_go_data_snapshot; then exit 1; fi
  [ ! -e "$go_data_stage/copying" ] && [ ! -e "$go_data_stage/original" ]
  rmdir "$go_data_path"
  mv "$tmp/detached-data" "$go_data_path"
  save_go_data_snapshot
  printf 'settings from the new panel\n' > "$DATA/config"
  [ "$(cat "$go_data_stage/original/config")" = 'final settings from Go' ]
  [ -L "$DATA" ] && [ "$(readlink "$DATA")" = "$go_data_path" ]

  rm -f "$stage/data-location"
  panel_inode() {
    if [ "$1" = "$go_data_path" ]; then echo 1:10; else echo 2:20; fi
  }
  # Exercise the real cutover sequence. A cross-filesystem rollback target
  # must be rejected before routing preparation or delivery of TERM.
  awk '/^  prepare_go_data_snapshot \|\| die / {copy=1}
       copy {print}
       /^  save_go_data_snapshot \|\| die / && copy {exit}' "$src" > "$tmp/cutover"
  grep -q '^  if ! signal_panel ' "$tmp/cutover"
  prepare_go_routing() { touch "$tmp/unexpected-preparation"; }
  signal_panel() { touch "$tmp/unexpected-term"; }
  die() { exit 77; }
  result=0
  ( . "$tmp/cutover" ) || result=$?
  [ "$result" -eq 77 ] && [ ! -e "$stage/data-location" ]
  [ ! -e "$tmp/unexpected-preparation" ] && [ ! -e "$tmp/unexpected-term" ]
)

(
  sed -n '/^prepare_go_routing() (/,/^)/p' "$src" > "$tmp/prepare"
  . "$tmp/prepare"
  stage=$tmp/candidate
  mkdir "$stage"
  DATA=$tmp PORT=9080
  export CHECK_DIR=$tmp
  cat > "$stage/n2s" <<'EOF'
#!/bin/sh
if [ "$2" = --needs-ip ]; then cat "$CHECK_DIR/ip-needed"; exit; fi
if [ "$2" = --listen-address ]; then
  if [ "$3" = --supported ]; then echo panel-listener-v1
  else [ "$3" = 72/98765 ] || exit 1; printf '%s:%s\n' "$(cat "$CHECK_DIR/bind")" "$4"; fi
  exit
fi
if [ "$1" = resolve-panel-port ]; then
  if [ "$2" = --supported ]; then echo panel-port-v1
  elif [ -f "$CHECK_DIR/saved-port" ]; then cat "$CHECK_DIR/saved-port"
  else echo "$2"; fi
  exit
fi
[ "$2" = 127.0.0.2:9079 ] || { echo 'Go preparation addressed the wrong panel socket' >&2; exit 1; }
if [ "$(cat "$CHECK_DIR/ip-needed")" = yes ]; then [ -f "$CHECK_DIR/full-ip" ] || exit 1; fi
echo trial
EOF
  chmod +x "$stage/n2s"
  has_routing_ip() { [ -f "$tmp/full-ip" ]; }
  opkg() { [ "$1 $2" = "install ip-full" ] && touch "$tmp/full-ip"; }
  say() { :; }
  go_process=72/98765
  echo 127.0.0.2 > "$tmp/bind"
  go_listen=saved/127.0.0.2:9079
  resolve_handoff_ports
  [ "$go_endpoint" = 127.0.0.2:9079 ] && [ "$bind_host" = 127.0.0.2 ] && [ "$handoff_port" = 9080 ]
  echo 9095 > "$tmp/saved-port"
  resolve_handoff_ports
  [ "$go_endpoint" = 127.0.0.2:9095 ] && [ "$handoff_port" = 9095 ]
  echo '[::]' > "$tmp/bind"
  go_listen=saved/:9079
  resolve_handoff_ports
  [ -z "$bind_host" ] && [ "$go_endpoint" = '[::]:9095' ]
  echo '[::1]' > "$tmp/bind"
  go_listen=saved/localhost:9079
  resolve_handoff_ports
  [ "$bind_host" = '[::1]' ] && [ "$go_endpoint" = '[::1]:9095' ]
  go_listen=explicit/127.0.0.2:9079
  echo 127.0.0.2 > "$tmp/bind"
  resolve_handoff_ports
  [ "$go_port" = 9079 ] && [ "$handoff_port" = 9095 ]
  echo no > "$tmp/ip-needed"
  [ "$(prepare_go_routing "$go_endpoint")" = trial ] || exit 1
  [ ! -e "$tmp/full-ip" ]
  echo yes > "$tmp/ip-needed"
  if N2S_SKIP_DEPS=1 prepare_go_routing "$go_endpoint"; then exit 1; fi
  [ "$(prepare_go_routing "$go_endpoint")" = trial ] && [ -f "$tmp/full-ip" ]
)

(
  # Render the real Keenetic init and observe the executable's arguments.
  # Its synthetic process never writes a PID or binds a socket.
  INIT=$tmp/restricted-init BIN=$tmp/listen-probe LOG_DIR=$tmp/log RUN_DIR=$tmp/empty-run
  PORT=9080 bind_host='[::1]' selective_accel=0
  export OBSERVED_LISTEN=$tmp/observed-listen
  awk '/^  cat > "\$INIT" <<EOF$/ {block++}
    block==2 && /^  chmod \+x "\$INIT"/ {exit}
    block==2 {print}' "$src" > "$tmp/render-keenetic"
  . "$tmp/render-keenetic"
  grep -Fxq "BIND_HOST='[::1]'" "$INIT"
  cat > "$BIN" <<'EOF'
#!/bin/sh
[ "$1" = serve ] && [ "$3" = -l ] && printf '%s\n' "$4" > "$OBSERVED_LISTEN"
EOF
  chmod +x "$BIN"
  set -- fixture
  . "$INIT" >/dev/null
  sleep() { :; }
  start >/dev/null 2>&1 && exit 1
  [ "$(cat "$OBSERVED_LISTEN")" = '[::1]:9080' ]
)

sed -n '/^snapshot_go_sets() (/,/^)/p; /^capture_go_source() {/,/^}/p; /^restore_live_compact() {/,/^}/p; /^shell_epoch() {/,/^}/p; /^claim_go_restore() {/,/^}/p; /^old_go_files() {/,/^}/p; /^resume_go_restore() {/,/^}/p; /^restore_go() {/,/^}/p; /^release_parked_go_guard() (/,/^)/p; /^verify_go_services() {/,/^}/p; /^cleanup_stage() {/,/^}/p' "$src" > "$tmp/restore-functions"
sed "s#/proc/#$tmp/proc/#g" "$tmp/restore-functions" > "$tmp/fake-restore-functions"
. "$tmp/fake-restore-functions"
shell_epoch() { [ "$1" = "$$" ] && echo 7373; }
(
  DATA=$tmp PORT=9080 BIN=fixture_bin
  rollback_go=1 cap=0
  fixture_bin() {
    [ "$1" = finish-go-services ] || return 1
    if [ "$2" = --supported ]; then [ "$cap" = 1 ] && echo go-services-v1; return; fi
    [ "$N2S_DATA" = "$DATA" ] && [ "$2" = 9095 ] && [ -f "$tmp/service-ready" ]
  }
  verify_go_services 9095
  cap=1
  if verify_go_services 9095; then exit 1; fi
  touch "$tmp/service-ready"
  verify_go_services 9095
  rollback_go=0
  rm "$tmp/service-ready"
  verify_go_services 9095
)
stage=$tmp/stage
go_data_path=$tmp/linked-data
go_data_stage=$tmp/data-backup
DATA=$tmp/data
BIN=$tmp/n2s
INIT=$tmp/init
export TEST_ACTIONS=$tmp/actions FIXTURE_DATA=$DATA FIXTURE_ROOT=$tmp
mkdir "$stage" "$go_data_path" "$go_data_stage"
ln -s "$go_data_path" "$DATA"
: > "$TEST_ACTIONS"
cat > "$stage/n2s" <<'EOF'
#!/bin/sh
set -eu
[ "$1" != release-native-clients ] || {
  if [ "${2:-}" = --supported ]; then echo native-client-release-v1; exit; fi
  [ "$N2S_DATA" = "$FIXTURE_DATA" ] && [ ! -f "$FIXTURE_ROOT/new-process" ] || exit 1
  echo clients >> "$TEST_ACTIONS"
  [ ! -f "$FIXTURE_ROOT/clients-blocked" ]; exit
}
[ "$1" = release-go-routing ] || exit 1
if [ "${2:-}" = --supported ]; then echo go-routing-release-v1; exit; fi
[ "$N2S_DATA" = "$FIXTURE_DATA" ] || exit 1
journal="$N2S_DATA/.store/runtime/awg-static-ipv4.json"
if [ -e "$journal" ]; then [ "$(cat "$journal")" = owned ] || exit 1
else [ -e "$N2S_DATA/.store/runtime/test-checkpoint" ] || exit 1; fi
if [ "${2:-}" = --checkpoint ]; then
  [ "$#" = 2 ] || exit 1
  echo checkpoint >> "$TEST_ACTIONS"
  [ ! -e "$FIXTURE_ROOT/checkpoint-blocked" ] || exit 1
  touch "$N2S_DATA/.store/runtime/test-checkpoint"
  exit
fi
[ "$#" = 1 ] && [ ! -e "$FIXTURE_ROOT/new-process" ] && [ -f "$N2S_DATA/.store/runtime/test-checkpoint" ] || exit 1
echo release >> "$TEST_ACTIONS"
[ ! -e "$FIXTURE_ROOT/cleanup-blocked" ] || exit 1
rm -f "$journal" || exit 1
if [ -e "$FIXTURE_ROOT/restart-during-release" ]; then
  printf '91/2345' > "$FIXTURE_ROOT/new-process"
  echo owned > "$journal"
  rm "$FIXTURE_ROOT/restart-during-release"
fi
echo released
EOF
chmod +x "$stage/n2s"
printf 'original\n' > "$BIN"
printf 'config\n' > "$DATA/config"
cat > "$INIT" <<'EOF'
#!/bin/sh
if [ -f "$FIXTURE_ROOT/start-blocked" ]; then echo start-blocked >> "$TEST_ACTIONS"; exit 1; fi
if [ -f "$FIXTURE_ROOT/late-restore" ]; then echo 101/7777 > "$FIXTURE_ROOT/go-process"; fi
printf '%s\n' "$1" >> "$TEST_ACTIONS"
EOF
chmod +x "$INIT"
cp -p "$INIT" "$stage/go-init"
cp -p "$BIN" "$stage/go-bin"
go_inode=$(panel_inode "$BIN")
new_inode=$(panel_inode "$stage/n2s")
go_process=72/98765
go_term_sent=0
process_file() {
  if [ "$1" = "$new_inode" ]; then printf '%s/new-process' "$tmp"; else printf '%s/go-process' "$tmp"; fi
}
find_panel() { cat "$(process_file "$1")" 2>/dev/null || true; }
signal_panel() { printf 'term %s\n' "$1" >> "$TEST_ACTIONS"; }
wait_panel_exit() {
  printf 'wait %s\n' "$1" >> "$TEST_ACTIONS"
  [ ! -e "$tmp/busy" ] || return 1
  rm -f "$(process_file "$2")"
}
printf '%s' "$go_process" > "$tmp/go-process"
restore_go
[ ! -s "$TEST_ACTIONS" ]
go_term_sent=1
restore_go
[ "$(cat "$TEST_ACTIONS")" = "$(printf 'wait 72/98765\nstart')" ]

# A partially written new init may no longer work. Do not call it to stop a
# process or assume that its PID file disappears before the process exits.
go_trial=trial
rollback_go=1 go_preparing=1 rollback_compact=0 snapshot_started=0
say() { printf '%s\n' "$*" >> "$tmp/messages"; }
mkdir -p "$DATA/.store/runtime"
for record in awg-go-handoff awg-go-trial-check awg-go-clients-pending awg-go-release upgrade-go-services; do
  touch "$DATA/.store/runtime/$record.json"
done
cp -a "$go_data_path" "$go_data_stage/original"
printf 'new-config\n' > "$DATA/config"
printf 'owned\n' > "$DATA/.store/runtime/awg-static-ipv4.json"
mv -f "$stage/n2s" "$BIN"
printf 'incomplete init\n' > "$INIT"
printf '89/1234' > "$tmp/new-process"
touch "$tmp/checkpoint-blocked"
: > "$TEST_ACTIONS"
if restore_go; then echo 'stopped Rust without a checkpoint' >&2; exit 1; fi
[ "$(cat "$TEST_ACTIONS")" = checkpoint ] && [ "$(cat "$tmp/new-process")" = 89/1234 ]
rm "$tmp/checkpoint-blocked"
touch "$tmp/busy"
if restore_go; then echo 'restored files over a live Rust process' >&2; exit 1; fi
[ "$(cat "$DATA/config")" = new-config ] && [ "$(panel_inode "$BIN")" = "$new_inode" ]
[ -f "$go_data_stage/original/config" ]
rm "$tmp/busy"
: > "$TEST_ACTIONS"
touch "$tmp/cleanup-blocked"
if cleanup_stage; then echo 'reported Go restored with an unreleased Rust journal' >&2; exit 1; fi
[ ! -e "$tmp/new-process" ] && [ ! -e "$go_data_stage/failed" ]
[ "$(cat "$DATA/.store/runtime/awg-static-ipv4.json")" = owned ]
[ "$(cat "$DATA/config")" = new-config ] && [ "$(cat "$go_data_stage/original/config")" = config ]
[ "$(panel_inode "$BIN")" = "$new_inode" ] && [ -f "$stage/go-init" ] && [ -f "$stage/go-bin" ]
grep -q '^release$' "$TEST_ACTIONS"
if grep -qx start "$TEST_ACTIONS" || grep -q 'previous Keenetic panel restored' "$tmp/messages"; then exit 1; fi
rm "$tmp/cleanup-blocked"
: > "$TEST_ACTIONS"
touch "$tmp/restart-during-release"
if cleanup_stage; then echo 'swapped data under a panel that restarted during release' >&2; exit 1; fi
[ "$(cat "$tmp/new-process")" = 91/2345 ] && [ ! -e "$go_data_stage/failed" ]
[ "$(cat "$DATA/.store/runtime/awg-static-ipv4.json")" = owned ]
[ "$(cat "$DATA/config")" = new-config ] && [ -f "$go_data_stage/original/config" ]
if grep -qx start "$TEST_ACTIONS"; then exit 1; fi
# Exhausting space while staging the old init must leave the snapshot reusable.
cp() {
  if [ "${2:-}" = "$stage/go-init" ] && [ -e "$tmp/copy-blocked" ]; then return 1; fi
  command cp "$@"
}
touch "$tmp/copy-blocked"
: > "$TEST_ACTIONS"
if cleanup_stage; then echo 'accepted a failed copy of the rollback init' >&2; exit 1; fi
[ ! -e "$go_data_stage/failed" ] && [ "$(cat "$go_data_stage/original/config")" = config ]
[ "$(cat "$DATA/config")" = new-config ] && [ "$(panel_inode "$BIN")" = "$new_inode" ]
if grep -qx start "$TEST_ACTIONS"; then exit 1; fi
rm "$tmp/copy-blocked"
: > "$TEST_ACTIONS"
touch "$tmp/clients-blocked"
go_trial=inactive
if cleanup_stage; then echo 'restarted Go with unreleased Rust clients' >&2; exit 1; fi
grep -qx clients "$TEST_ACTIONS"
if grep -qx start "$TEST_ACTIONS"; then exit 1; fi
[ ! -e "$go_data_stage/failed" ] && [ "$(cat "$DATA/config")" = new-config ]
rm "$tmp/clients-blocked"
go_trial=trial
: > "$TEST_ACTIONS"
touch "$tmp/late-restore" "$tmp/data-blocked" "$tmp/rename-blocked"
mv() {
  if [ "${1:-}" = "$go_data_stage/original" ] && [ "${2:-}" = "$go_data_path" ] && [ -f "$tmp/data-blocked" ]; then
    rm "$tmp/data-blocked"
    return 1
  fi
  if [ "${2:-}" = "$stage/rollback-init" ] && [ "${3:-}" = "$INIT" ] && [ -f "$tmp/rename-blocked" ]; then
    rm "$tmp/rename-blocked"
    return 1
  fi
  command mv "$@"
}
if cleanup_stage; then echo 'ignored incomplete data directory replacement' >&2; exit 1; fi
[ ! -e "$tmp/data-blocked" ] && [ ! -e "$go_data_path" ] && [ -L "$DATA" ]
[ "$(cat "$go_data_stage/original/config")" = config ] && [ "$(cat "$go_data_stage/failed/config")" = new-config ]
if cleanup_stage; then echo 'ignored transient init rename failure' >&2; exit 1; fi
[ ! -e "$tmp/rename-blocked" ] && [ -f "$stage/rollback-state" ]
[ "$(cat "$DATA/config")" = config ] && [ "$(cat "$go_data_stage/failed/config")" = new-config ]
echo 'post-restore change' > "$DATA/user-change"
saved_id=$(panel_inode "$go_data_path")
mv "$go_data_path" "$tmp/manual-data"
mkdir "$go_data_path"
if cleanup_stage; then echo 'replaced a foreign data directory during recovery' >&2; exit 1; fi
[ -d "$go_data_path" ] && rmdir "$go_data_path" && mv "$tmp/manual-data" "$go_data_path"
printf 'operator init edit\n' >> "$INIT"
if cleanup_stage; then echo 'overwrote a foreign init change during recovery' >&2; exit 1; fi
cat "$stage/candidate-init" > "$INIT"
touch "$tmp/start-blocked"
if cleanup_stage; then echo 'reported an unconfirmed Go start as recovered' >&2; exit 1; fi
[ -f "$stage/rollback-state" ] && [ -f "$stage/rollback-payload-ready" ]
[ "$(cat "$BIN")" = original ] && [ "$(cat "$DATA/user-change")" = 'post-restore change' ]
rm "$tmp/start-blocked"
# A new installer must recover from the receipt without the old shell variables.
touch "$tmp/cleanup-interrupted"
rm() {
  if [ "${1:-}" = -rf ] && [ "${2:-}" = "$stage" ] && [ -f "$tmp/cleanup-interrupted" ]; then
    command rm "$tmp/cleanup-interrupted"
    return 1
  fi
  command rm "$@"
}
if (unset go_data_stage go_data_path new_inode go_inode snapshot_started rollback_compact compact_backup
  rollback_go=1 go_preparing=1
  cleanup_stage); then echo 'ignored incomplete stage cleanup' >&2; exit 1; fi
[ ! -d "$go_data_stage" ] && [ -f "$stage/rollback-cleaning" ] && [ ! -e "$tmp/cleanup-interrupted" ]
unset -f rm
(unset go_data_stage go_data_path new_inode go_inode snapshot_started rollback_compact compact_backup
  rollback_go=1 go_preparing=1
  cleanup_stage)
unset -f mv
case "$(cat "$TEST_ACTIONS")" in
  "$(printf 'checkpoint\nrelease\nclients\nstart-blocked\nstart')"|"$(printf 'checkpoint\nterm 91/2345\nwait 91/2345\nrelease\nclients\nstart-blocked\nstart')") ;;
  *) echo 'expected successful release before one Go start' >&2; exit 1 ;;
esac
grep -q 'previous Keenetic panel restored' "$tmp/messages"
[ "$(cat "$DATA/config")" = config ] && [ "$(cat "$BIN")" = original ]
[ -L "$DATA" ] && [ ! -e "$go_data_stage" ] && [ ! -e "$stage" ]
[ "$(panel_inode "$go_data_path")" = "$saved_id" ] && [ "$(cat "$DATA/user-change")" = 'post-restore change' ]
rm "$tmp/go-process"
for record in awg-go-handoff awg-go-trial-check awg-go-clients-pending awg-go-release upgrade-go-services awg-static-ipv4; do
  [ ! -e "$DATA/.store/runtime/$record.json" ] || exit 1
done

(
  sed -n '/^retire_compact_snapshot() (/,/^)/p; /^snapshot_compact() {/,/^}/p; /^restore_compact() {/,/^}/p' "$src" > "$tmp/compact-functions"
  . "$tmp/compact-functions"
  stage=$tmp/compact-stage compact_dir=$tmp/compact-lib
  COMPACT_BIN=$compact_dir/n2s-compact repair_file=$compact_dir/.compact-repair
  go_data_stage=$tmp/compact-data-backup go_data_path=$tmp/compact-data
  BIN=$tmp/compact-link INIT=$tmp/compact-init DATA=$go_data_path
  active_profile=compact go_trial=inactive rollback_compact=0 snapshot_started=0
  selected=nfqws2-strategy-tgws
  mkdir "$stage" "$compact_dir" "$go_data_path" "$go_data_stage"
  ln -s "$COMPACT_BIN" "$BIN"
  printf 'Go compact\n' > "$COMPACT_BIN"
  chmod 700 "$COMPACT_BIN"
  rm -f "$procdir/exe"
  ln "$COMPACT_BIN" "$procdir/exe"
  printf '%s\000' "$BIN" serve -pid "$RUN_DIR/nfqws2-strategy.pid" > "$procdir/cmdline"
  printf '72\n' > "$RUN_DIR/nfqws2-strategy.pid"
  cat > "$INIT" <<'EOF'
#!/bin/sh
[ "$1" = start ] && [ "$(cat "$FIXTURE_ROOT/compact-link")" = 'Go compact' ] &&
  [ "$(cat "$FIXTURE_ROOT/compact-data/config")" = 'Go settings' ] &&
  echo 102/7778 > "$FIXTURE_ROOT/go-process" &&
  printf '%s\n' 'compact-start' >> "$TEST_ACTIONS"
EOF
  chmod 700 "$INIT"
  printf 'Go settings\n' > "$DATA/config"
  capture_go_source
  saved_inode=$go_inode
  snapshot_compact
  # opkg replaces COMPACT_BIN while Go still has the previous inode open.
  printf '#!/bin/sh\nexit 1\n' > "$stage/new"
  chmod 700 "$stage/new"
  mv -f "$stage/new" "$COMPACT_BIN"
  new_inode=$(panel_inode "$COMPACT_BIN")
  [ "$(panel_token 72 "$saved_inode")" = 72/98765 ] && [ "$new_inode" != "$saved_inode" ]
  [ "$(cat "$stage/go-bin")" = 'Go compact' ]
  cp -a "$DATA" "$go_data_stage/original"
  printf 'Rust settings\n' > "$DATA/config"
  printf 'incomplete init\n' > "$INIT"
  : > "$TEST_ACTIONS"
  # The staged link has already been moved into BIN. No Rust process remains.
  restore_go
  [ "$(cat "$TEST_ACTIONS")" = compact-start ]
  [ "$(readlink "$BIN")" = "$COMPACT_BIN" ] && [ "$rollback_compact" = 0 ]
  [ "$(cat "$repair_file")" = "$selected" ] && [ -f "$compact_backup/.ready" ]
)

stage=$tmp/set-snapshot
mkdir "$stage"
cat > "$stage/n2s" <<'SH'
#!/bin/sh
[ "$1" = prepare-go-routing ] && [ "$2" = --source-chain ] || exit 1
echo "$TEST_GO_CHAIN"
SH
chmod 700 "$stage/n2s"
TEST_GO_CHAIN=AWG2_MULTI
export TEST_GO_CHAIN
iptables() {
  if [ "$5" = PREROUTING ]; then printf '%s\n' '-A PREROUTING -j AWG2_MULTI' '-A PREROUTING -j AWG2_MULTI'; return; fi
  printf '%s\n' '-A AWG2_MULTI -m set --match-set awgm_003 dst -j RETURN' \
    '-A AWG2_MULTI -m set --match-set customer_set dst -j RETURN' \
    '-A AWG2_MULTI -m set --match-set awgm_004 src -j RETURN'
}
ipset() {
  [ "$1" = save ] && [ "$2" = awgm_003 ] || return 1
  printf '%s\n' 'create awgm_003 hash:net' 'add awgm_003 192.0.2.2 timeout 313'
}
snapshot_go_sets
[ "$(cat "$stage/go-sets")" = 'add awgm_003 192.0.2.2 timeout 313' ]
TEST_GO_CHAIN=AWG2_MARK
iptables() {
  case "$5" in
    PREROUTING) echo '-A PREROUTING -j AWG2_MARK' ;;
    AWG2_MARK)
      if [ "${zone_sets:-0}" = 1 ]; then
        printf '%s\n' '-A AWG2_MARK -s 192.0.2.2/32 -m set --match-set awg2_z0 dst -j RETURN' \
          '-A AWG2_MARK -s 198.51.100.0/24 -m set --match-set awg2_z1 dst -j MARK --set-xmark 0x10000000/0x10000000'
      fi
      if [ "${extra_set:-0}" = 1 ]; then echo '-A AWG2_MARK -m set --match-set awg2_inc dst -j RETURN'; fi
      echo '-A AWG2_MARK -j MARK --set-xmark 0x10000000/0x10000000' ;;
    *) return 1 ;;
  esac
}
snapshot_go_sets
[ ! -s "$stage/go-sets" ]
zone_sets=1
snapshot_go_sets
[ ! -s "$stage/go-sets" ]
extra_set=1
if snapshot_go_sets; then exit 1; fi
printf '%s\n' 'Keenetic Go upgrade ownership, DNS snapshot, and rollback passed'
