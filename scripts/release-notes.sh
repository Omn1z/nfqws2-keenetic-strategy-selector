#!/bin/sh
# Print exactly one release section from CHANGELOG.md. Fail closed if it is
# missing, duplicated, or empty so a tag cannot publish unrelated release notes.
# Usage: sh scripts/release-notes.sh v1.5.0 [CHANGELOG.md]
set -eu

VERSION="${1:?usage: release-notes.sh VERSION [CHANGELOG.md]}"
CHANGELOG="${2:-CHANGELOG.md}"

awk -v version="$VERSION" '
  BEGIN { heading = "## [" version "]" }
  { sub(/\r$/, "") }
  /^## / {
    capture = substr($0, 1, length(heading)) == heading &&
      (length($0) == length(heading) || substr($0, length(heading) + 1, 1) ~ /[ \t]/)
    if (capture) found++
    next
  }
  capture {
    if ($0 ~ /[^[:space:]]/) nonempty = 1
    body = body $0 "\n"
  }
  END {
    if (found != 1 || !nonempty) {
      print "Expected one nonempty changelog section for " version > "/dev/stderr"
      exit 1
    }
    sub(/^\n+/, "", body)
    sub(/\n+$/, "", body)
    print body
  }
' "$CHANGELOG"
