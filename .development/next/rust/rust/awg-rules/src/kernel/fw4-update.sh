set -eu
exec 9>/var/run/fw4.lock
flock -x 9

# fw4 network itself takes this same flock. Run its stock, read-only lookup
# under the lock already held, so a reload cannot recycle the old chain for
# another zone between validation and a forwarding grant. Removal is allowed
# when the former zone has vanished.
if [ -n "$2" ]; then
    if ! zone=$(ACTION=network OBJECT=lan QUIET=1 utpl -S /usr/share/firewall4/main.uc) ||
       [ -z "$4" ] || [ "$zone" != "$4" ]; then echo fw4-refused; exit 0; fi
fi

# Find matching handles in the current generation. An unexpected duplicate or
# missing rule aborts the entire batch, including additions.
if ! changes=$(
    {
        for chain in $3; do
            echo "chain:$chain"
            nft -a list chain inet fw4 "$chain" || { echo "list-failed"; break; }
        done
    } | awk -v remove="$1" -v add="$2" -v known="$5" '
        BEGIN {
            n = split(remove, rows, "\n")
            for (i = 1; i <= n; i++) if (rows[i] != "") del[rows[i]] = 1
            n = split(add, rows, "\n")
            for (i = 1; i <= n; i++) if (rows[i] != "") ins[rows[i]] = 1
            n = split(known, rows, "\n")
            for (i = 1; i <= n; i++) if (rows[i] != "") own[rows[i]] = 1
        }
        /^chain:/ { chain = substr($0, 7); next }
        /^list-failed$/ { bad = 1; next }
        /comment "n2s-awg-cidr" # handle [0-9]+$/ {
            handle = $NF
            sub(/^[[:space:]]+/, "")
            sub(/ # handle [0-9]+$/, "")
            key = chain "\t" $0
            if (add != "" && (!(key in own) || ++copies[key] > 1)) bad = 1
            if (key in ins) bad = 1
            if (key in del) {
                if (++seen[key] > 1) bad = 1
                print "delete rule inet fw4 " chain " handle " handle
            }
        }
        END {
            for (key in del) if (!(key in seen)) bad = 1
            if (bad) exit 1
            for (key in ins) {
                split(key, parts, "\t")
                print "add rule inet fw4 " parts[1] " " parts[2]
            }
        }
    '
); then echo fw4-refused; exit 0; fi
printf '%s\n' "$changes" | nft -f -
