#!/usr/bin/env bash
# Build only the reviewed, locked graph. Release packaging ships this output.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_FILE="$ROOT_DIR/capsules/wallet-walletconnect/vendor/reown-appkit.js"
if [[ "${1:-}" == --out-file ]]; then OUT_FILE="${2:?missing output path}"; shift 2; fi
[[ $# == 0 ]] || { echo 'Usage: scripts/vendor-walletconnect-adapter.sh [--out-file PATH]' >&2; exit 2; }
npm ci --prefix "$ROOT_DIR/scripts/walletconnect" --ignore-scripts --no-audit --no-fund
mkdir -p "$(dirname "$OUT_FILE")"
"$ROOT_DIR/scripts/walletconnect/node_modules/.bin/esbuild" "$ROOT_DIR/scripts/walletconnect/adapter.mjs" \
  --bundle --format=esm --platform=browser --target=es2022 --minify \
  --inject:"$ROOT_DIR/scripts/walletconnect/runtime-websocket.mjs" --outfile="$OUT_FILE"
node --input-type=module - "$ROOT_DIR" "$OUT_FILE" <<'JS'
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, copyFileSync, readdirSync, lstatSync } from 'node:fs';
import { dirname, join } from 'node:path';
const [root, output] = process.argv.slice(2);
copyFileSync(join(root, 'scripts/walletconnect/package-lock.json'), join(dirname(output), 'package-lock.json'));
const sha = path => createHash('sha256').update(readFileSync(path)).digest('hex');
writeFileSync(join(dirname(output), 'adapter.json'), JSON.stringify({
  sdk_package: '@walletconnect/ethereum-provider', sdk_version: '2.23.9',
  sdk_sha256: sha(output), dependency_lock_sha256: sha(join(root, 'scripts/walletconnect/package-lock.json')),
  source_sha256: Object.fromEntries(['adapter.mjs', 'runtime-storage.mjs', 'runtime-websocket.mjs', '../vendor-walletconnect-adapter.sh'].map(file =>
    [file, sha(join(root, 'scripts/walletconnect', file))])),
}, null, 2) + '\n');
const lock = JSON.parse(readFileSync(join(root, 'scripts/walletconnect/package-lock.json')));
const notices = [];
for (const name of Object.keys(lock.packages).filter(Boolean).sort()) {
  const directory = join(root, 'scripts/walletconnect', name);
  let files;
  try { files = readdirSync(directory).filter(file => /^(license|licence|copying|notice)(\.|$)/i.test(file)); }
  catch { continue; } // Optional dependencies for another host are locked, but absent.
  for (const file of files.filter(file => lstatSync(join(directory, file)).isFile())) notices.push(`${name}/${file}\n${readFileSync(join(directory, file), 'utf8')}`);
}
writeFileSync(join(dirname(output), 'LICENSES.txt'), notices.join('\n\n'));
JS
