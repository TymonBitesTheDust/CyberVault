// Builds dist/cybervault.html: the whole app (code, styles, font, logo) in ONE file.
// Usage (from the project folder):  node tools/build-single-file.mjs
// The Firebase config lives in a clearly marked block near the top of the output file.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const pub = (p) => join(root, 'public', p);
const read = (p) => readFileSync(pub(p), 'utf8');
const dataUrl = (p, mime) => `data:${mime};base64,${readFileSync(pub(p)).toString('base64')}`;

// 1. vault-crypto.js → an object `vc` (strip `export`, collect the exported names)
const cryptoSrc = read('vault-crypto.js');
const names = [...cryptoSrc.matchAll(/^export (?:async function|function|const|class) ([A-Za-z_$][\w$]*)/gm)].map((m) => m[1]);
const vcBlock = `const vc = (() => {\n${cryptoSrc.replace(/^export /gm, '')}\nreturn { ${names.join(', ')} };\n})();\n`;

// 1b. qr.js (the Wi-Fi QR code generator), the same way
const qrSrc = read('qr.js');
const qrNames = [...qrSrc.matchAll(/^export (?:async function|function|const|class) ([A-Za-z_$][\w$]*)/gm)].map((m) => m[1]);
const qrBlock = `const { ${qrNames.join(', ')} } = (() => {\n${qrSrc.replace(/^export /gm, '')}\nreturn { ${qrNames.join(', ')} };\n})();\n`;

// 2. app.js: inline vc, read the config from the page, embed the logo
const logo = dataUrl('icons/logo.svg', 'image/svg+xml');
let app = read('app.js');
const swap = (from, to) => {
  if (!app.includes(from)) throw new Error(`build: can't find ${from}`);
  app = app.split(from).join(to);
};
swap("import * as vc from './vault-crypto.js';\n", vcBlock);
swap("import { qrSvg, wifiQrText } from './qr.js';\n", qrBlock);
// The app reads the FIREBASE CONFIG block itself (see embeddedConfig in app.js).
swap("import { firebaseConfig } from './firebase-config.js';\n", 'const firebaseConfig = null;\n');
swap("'icons/logo.svg'", JSON.stringify(logo));
if (app.includes('</script')) throw new Error('build: app code contains </script');

// 3. CSS with the fonts embedded
let css = read('styles.css');
for (const w of [400, 500, 700, 800]) {
  css = css.split(`url("fonts/jetbrains-mono-${w}.woff2")`).join(`url("${dataUrl(`fonts/jetbrains-mono-${w}.woff2`, 'font/woff2')}")`);
}

// 4. Config block for the user to fill in (copied from firebase-config.js)
const cfg = read('firebase-config.js');
const cfgObj = cfg.slice(cfg.indexOf('{'), cfg.lastIndexOf('}') + 1);

// 5. Page, with a CSP hash that allows exactly this inline script
const hash = createHash('sha256').update(app, 'utf8').digest('base64');
const csp = [
  "default-src 'self'",
  `script-src 'sha256-${hash}' https://www.gstatic.com https://apis.google.com https://www.google.com`,
  "style-src 'self' 'unsafe-inline'",
  "font-src data:",
  "img-src 'self' blob: data:",
  "connect-src 'self' https://*.googleapis.com https://*.firebaseio.com https://*.firebaseapp.com https://apis.google.com https://www.google.com",
  "frame-src https://*.firebaseapp.com https://*.web.app https://accounts.google.com https://apis.google.com https://www.google.com https://recaptcha.google.com",
  "worker-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
].join('; ');

const html = `<!doctype html>
<html lang="en-AU">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<meta name="theme-color" content="#050807">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black">
<meta name="apple-mobile-web-app-title" content="CyberVault">
<meta name="format-detection" content="telephone=no">
<title>CyberVault</title>
<link rel="icon" type="image/svg+xml" href="${logo}">

<!-- ================= FIREBASE CONFIG (optional) =========================================
     Leave the placeholders to connect inside the app instead (a "Connect Firebase" screen
     appears on first open). Or paste your firebaseConfig here (Firebase console → Project
     settings → Your apps) so every device is connected automatically. Not secret.          -->
<script type="text/plain" id="firebase-config">
const firebaseConfig = ${cfgObj};
</script>
<!-- ===================================================================================== -->

<style>
${css}
</style>
<script type="module">${app}</script>
</head>
<body>
<div id="app"><div class="boot">Loading CyberVault…</div></div>
<div id="toasts" aria-live="polite"></div>
</body>
</html>
`;
mkdirSync(join(root, 'dist'), { recursive: true });
writeFileSync(join(root, 'dist', 'cybervault.html'), html);
// Optional companion: upload sw.js next to cybervault.html so the app also opens offline.
writeFileSync(join(root, 'dist', 'sw.js'), read('sw.js'));
console.log(`dist/cybervault.html written (${(html.length / 1024).toFixed(0)} KB), plus dist/sw.js for offline start-up`);
