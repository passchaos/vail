#!/usr/bin/env bash
set -euo pipefail
out=${1:?output hex path}
work=$(mktemp -d)
cleanup() {
  if [[ -n "${pid:-}" ]]; then kill "$pid" 2>/dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT
openssl req -newkey rsa:2048 -nodes -keyout "$work/key.pem" -x509 -days 1 -out "$work/cert.pem" -subj /CN=localhost >/dev/null 2>&1
openssl s_server -accept 24443 -cert "$work/cert.pem" -key "$work/key.pem" -www >"$work/server.log" 2>&1 &
pid=$!
sleep 0.3
(openssl s_client -connect 127.0.0.1:24443 -tls1_3 -servername example.com -alpn h2 -msg </dev/null > "$work/sclient_msg.txt" 2>&1 || true)
python3 - "$work/sclient_msg.txt" "$out" <<'PY'
from pathlib import Path
import sys
lines=Path(sys.argv[1]).read_text(errors='ignore').splitlines()
collect=False; hexparts=[]
for line in lines:
    if 'ClientHello' in line and '>>>' in line:
        collect=True
        continue
    if collect:
        if line.startswith('>>>') or line.startswith('<<<') or line.startswith('SSL') or line.startswith('CONNECTED') or line.startswith('---') or line.startswith('depth='):
            break
        s=''.join(line.strip().split())
        if s and all(c in '0123456789abcdefABCDEF' for c in s):
            hexparts.append(s)
hexstr=''.join(hexparts)
if not hexstr:
    raise SystemExit('no ClientHello found')
Path(sys.argv[2]).write_text(hexstr + '\n')
PY
