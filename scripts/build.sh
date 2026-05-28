#!/bin/sh
# Cross-compile static binaries for common Keenetic/Entware architectures.
# Usage: sh scripts/build.sh [version]
set -e
VERSION="${1:-dev}"
OUT=dist
mkdir -p "$OUT"
LD="-s -w -X main.version=$VERSION"
PKG=./cmd/nfqws2-strategy

echo "building version=$VERSION"
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "$LD" -o "$OUT/nfqws2-strategy-linux-arm64" "$PKG"
GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build -trimpath -ldflags "$LD" -o "$OUT/nfqws2-strategy-linux-arm" "$PKG"
GOOS=linux GOARCH=mipsle GOMIPS=softfloat CGO_ENABLED=0 go build -trimpath -ldflags "$LD" -o "$OUT/nfqws2-strategy-linux-mipsle" "$PKG"
GOOS=linux GOARCH=mips GOMIPS=softfloat CGO_ENABLED=0 go build -trimpath -ldflags "$LD" -o "$OUT/nfqws2-strategy-linux-mips" "$PKG"
ls -la "$OUT"
