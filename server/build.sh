#!/usr/bin/env bash
# Build the patched odoh-server-go as a static linux/amd64 binary.
set -euo pipefail
git clone --depth 1 https://github.com/cloudflare/odoh-server-go
cd odoh-server-go
git apply ../0001-env-configurable-nameservers.patch
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o ../hns-odoh .
echo "built: server/hns-odoh"
