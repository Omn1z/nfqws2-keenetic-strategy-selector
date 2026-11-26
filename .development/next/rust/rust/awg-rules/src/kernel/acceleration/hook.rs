use super::{io, Kernel, Saved};

const HOOK_PATH: &str = "/opt/etc/ndm/netfilter.d/89-n2s-rust-acceleration.sh";
// All writes use the kernel's existing NDM event. Never invoke ndmc here:
// it can queue another firewall event recursively.
fn body(saved: &Saved) -> String {
    format!(
        r#"#!/bin/sh
# nfqws2-strategy rust PPE {}
set -e
[ "$(cat /proc/sys/kernel/random/boot_id)" = '{}' ] || exit 0
for key in {}; do
  path=/proc/sys/$(printf '%s' "$key" | tr . /)
  if [ -e "$path" ] && [ "$(cat "$path")" != 0 ]; then sysctl -w "$key=0" >/dev/null; fi
done
if [ -w /proc/sys/net/hwnat/ppe_flush ]; then sysctl -w net.hwnat.ppe_flush=1 >/dev/null; fi
if [ -w /proc/sys/net/core/swnat_reset ]; then sysctl -w net.core.swnat_reset=1 >/dev/null; fi
"#,
        saved.id,
        saved.boot,
        super::FLAGS.join(" ")
    )
}
const ACTION: &str = r#"set -eu
file=$1; mode=$2; dir=${file%/*}
if [ ! -d "$dir" ]; then [ "$mode" = remove ] && exit 0; mkdir -p "$dir"; fi
[ ! -L "$file" ] || exit 1
if [ -e "$file" ]; then
  [ -f "$file" ] && cmp -s - "$file" || exit 1
  if [ "$mode" = remove ]; then rm "$file"; else [ -x "$file" ]; fi
  exit
fi
[ "$mode" = install ] || exit 0
tmp=$(mktemp "$dir/.n2s-ppe.XXXXXX") || exit 1
trap 'rm -f "$tmp"' EXIT
cat >"$tmp"
chmod 0755 "$tmp" && ln "$tmp" "$file""#;
pub(super) fn set(k: &Kernel<'_>, saved: &Saved, install: bool) -> io::Result<()> {
    k.run
        .run_input(
            "sh",
            &[
                "-c",
                ACTION,
                "awg-ppe-hook",
                HOOK_PATH,
                if install { "install" } else { "remove" },
            ],
            body(saved).as_bytes(),
            k.deadline,
        )
        .map(drop)
}
