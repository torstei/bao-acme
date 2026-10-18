#!/usr/bin/env bash
# Runs a throwaway OpenBao dev server with the freshly built plugin mounted at
# certificates/. Root token: root. Listens on DEV_LISTEN (default
# 127.0.0.1:18200), never on $BAO_ADDR. Stop with Ctrl-C.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
plugin_dir="$root/bin"
plugin=bao-acme
mount=${MOUNT:-certificates}
listen=${DEV_LISTEN:-127.0.0.1:18200}
export BAO_ADDR=http://$listen
export BAO_TOKEN=root

[[ -x "$plugin_dir/$plugin" ]] || { echo "build first: make build" >&2; exit 1; }

config=$(mktemp)
log=$(mktemp)
trap 'kill "$server" 2>/dev/null; rm -f "$config"' EXIT
echo "plugin_directory = \"$plugin_dir\"" > "$config"

bao server -dev -dev-root-token-id=root -dev-listen-address="$listen" -config="$config" >"$log" 2>&1 &
server=$!

for _ in $(seq 50); do
    kill -0 "$server" 2>/dev/null || { cat "$log" >&2; exit 1; }
    bao status >/dev/null 2>&1 && break
    sleep 0.1
done
bao status >/dev/null || { cat "$log" >&2; exit 1; }

bao plugin register -sha256="$(sha256sum "$plugin_dir/$plugin" | cut -d' ' -f1)" secret "$plugin" >/dev/null
bao secrets enable -path="$mount" "$plugin" >/dev/null

cat <<EOF
OpenBao dev server at $BAO_ADDR, root token "root", plugin mounted at $mount/.
Server log: $log

  export BAO_ADDR=$BAO_ADDR BAO_TOKEN=root
  bao write $mount/certs/example.com/import fullchain=@fullchain.pem privkey=@privkey.pem
  bao read  $mount/certs/example.com/info

EOF
wait "$server"
