#!/usr/bin/env bash
# Builds dist/CyberVault.exe: the Windows 10/11 app (64-bit). It's the web app in public/ inside a
# small native window (Microsoft Edge WebView2, which is built into Windows), with the Firebase SDK
# bundled, so the app never downloads and runs code. One file, no installer.
#
# Needs Go 1.24+ and Node.js (npm). Works on Linux, macOS or Windows (Git Bash or WSL):
#   tools/build-exe.sh
#
# The icon and file details come from desktop/rsrc_windows_amd64.syso. If x86_64-w64-mingw32-windres
# is installed (Debian/Ubuntu: sudo apt install binutils-mingw-w64-x86-64), it's remade from
# public/icons and the current version; otherwise the committed copy is used.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
for tool in go npm node; do
  command -v "$tool" >/dev/null || { echo "Missing '$tool'. Install Go (https://go.dev/dl) and Node.js (https://nodejs.org)." >&2; exit 1; }
done

APP_VERSION="$(sed -n "s/^const APP_VERSION = '\([0-9]*\.[0-9]*\.[0-9]*\)';/\1/p" public/app.js)"
[ -n "$APP_VERSION" ] || { echo "Couldn't find APP_VERSION in public/app.js" >&2; exit 1; }
FIREBASE_VERSION="$(grep -o 'firebasejs/[0-9.]*' public/app.js | head -1 | cut -d/ -f2)"
ASSETS="$ROOT/desktop/assets"

echo "› Copying the web app ($APP_VERSION)"
rm -rf "$ASSETS/www" "$ASSETS/firebasejs"
mkdir -p "$ASSETS/www" "$ASSETS/firebasejs/$FIREBASE_VERSION" "$ROOT/dist"
cp -R public/. "$ASSETS/www/"
# Not needed in the app: its files are already on the PC, and it isn't installed from the browser.
rm -f "$ASSETS/www/sw.js" "$ASSETS/www/manifest.webmanifest"

echo "› Bundling the Firebase SDK $FIREBASE_VERSION"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
( cd "$TMP" && npm pack --silent "firebase@$FIREBASE_VERSION" >/dev/null \
  && tar -xzf "firebase-$FIREBASE_VERSION.tgz" package/firebase-app.js package/firebase-auth.js package/firebase-firestore.js )
mv "$TMP"/package/*.js "$ASSETS/firebasejs/$FIREBASE_VERSION/"
cat > "$ASSETS/firebasejs/$FIREBASE_VERSION/NOTICE.txt" <<NOTICE
Firebase JavaScript SDK $FIREBASE_VERSION, copyright Google LLC.
Licensed under the Apache License, Version 2.0: https://www.apache.org/licenses/LICENSE-2.0
Source: https://github.com/firebase/firebase-js-sdk
NOTICE

echo "› Pointing the app at the bundled copies"
node - "$ASSETS" <<'JS'
const fs = require('fs');
const path = require('path');
const assets = process.argv[2];
const swapCdn = (file) => {
  const src = fs.readFileSync(file, 'utf8');
  const out = src.split('https://www.gstatic.com/firebasejs/').join('/firebasejs/');
  if (out === src && file.endsWith('app.js')) throw new Error(`No Firebase imports found in ${file}`);
  fs.writeFileSync(file, out);
};
swapCdn(path.join(assets, 'www/app.js'));
const sdk = path.join(assets, 'firebasejs');
for (const v of fs.readdirSync(sdk)) for (const f of fs.readdirSync(path.join(sdk, v))) if (f.endsWith('.js')) swapCdn(path.join(sdk, v, f));
// Tell the page it's inside the Windows app.
const index = path.join(assets, 'www/index.html');
const html = fs.readFileSync(index, 'utf8');
if (!html.includes('<head>')) throw new Error('No <head> in index.html');
fs.writeFileSync(index, html.replace('<head>', '<head>\n  <meta name="cybervault-shell" content="windows">'));
JS

if command -v x86_64-w64-mingw32-windres >/dev/null; then
  echo "› Making the icon and file details"
  "$ROOT/tools/make-windows-resources.sh" "$APP_VERSION"
elif ! grep -qx "$APP_VERSION" desktop/winres/version.txt 2>/dev/null; then
  echo "  ! desktop/rsrc_windows_amd64.syso was made for version $(cat desktop/winres/version.txt 2>/dev/null || echo '?'),"
  echo "    so CyberVault.exe's file details will show that version. Install windres to update it (see the top of this file)."
fi

echo "› Compiling"
( cd desktop && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-H windowsgui -s -w" -o "$ROOT/dist/CyberVault.exe" . )
echo "✓ dist/CyberVault.exe, version $APP_VERSION ($(du -h dist/CyberVault.exe | cut -f1))"
