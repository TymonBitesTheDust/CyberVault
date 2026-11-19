#!/usr/bin/env bash
# Makes desktop/rsrc_windows_amd64.syso: CyberVault.exe's icon, Windows manifest (sharp text on
# high-DPI screens) and file details (name, version, copyright). Go links it in automatically.
# Needs x86_64-w64-mingw32-windres, rsvg-convert and Python 3 with Pillow
# (Debian/Ubuntu: sudo apt install binutils-mingw-w64-x86-64 librsvg2-bin python3-pil).
# Usage: tools/make-windows-resources.sh 2.0.0   (tools/build-exe.sh runs it for you)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:?usage: $0 VERSION}"
IFS=. read -r MAJOR MINOR PATCH <<< "$VERSION"
OUT="$ROOT/desktop/winres"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# The icon: the logo drawn at each size Windows uses, so small sizes stay crisp.
for s in 16 20 24 32 40 48 64 128 256; do
  rsvg-convert -w "$s" -h "$s" "$ROOT/public/icons/logo.svg" -o "$TMP/$s.png"
done
python3 - "$TMP" "$OUT/cybervault.ico" <<'PY'
import sys
from PIL import Image
tmp, out = sys.argv[1], sys.argv[2]
sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]
imgs = [Image.open(f"{tmp}/{s}.png").convert("RGBA") for s in sizes]
imgs[-1].save(out, format="ICO", sizes=[(s, s) for s in sizes], append_images=imgs[:-1])
PY

cat > "$OUT/cybervault.manifest" <<'XML'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0" xmlns:asmv3="urn:schemas-microsoft-com:asm.v3">
  <assemblyIdentity type="win32" name="CyberVault" version="1.0.0.0" processorArchitecture="amd64"/>
  <description>CyberVault</description>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0"
        processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security>
  </trustInfo>
  <asmv3:application>
    <asmv3:windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </asmv3:windowsSettings>
  </asmv3:application>
</assembly>
XML

cat > "$TMP/cybervault.rc" <<RC
1 ICON "$OUT/cybervault.ico"
1 24 "$OUT/cybervault.manifest"
1 VERSIONINFO
FILEVERSION $MAJOR,$MINOR,$PATCH,0
PRODUCTVERSION $MAJOR,$MINOR,$PATCH,0
FILEOS 0x40004
FILETYPE 0x1
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904B0"
    BEGIN
      VALUE "CompanyName", "Tymon Ng"
      VALUE "FileDescription", "CyberVault"
      VALUE "FileVersion", "$VERSION"
      VALUE "InternalName", "CyberVault"
      VALUE "LegalCopyright", "Copyright (c) 2026 Tymon Ng. MIT licence."
      VALUE "OriginalFilename", "CyberVault.exe"
      VALUE "ProductName", "CyberVault"
      VALUE "ProductVersion", "$VERSION"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
RC
# windres runs the C preprocessor first. This file needs none, so without MinGW's gcc a
# pass-through stands in for it.
PRE=()
if ! command -v x86_64-w64-mingw32-gcc >/dev/null; then
  printf '#!/bin/sh\nfor last; do :; done\ncat "$last"\n' > "$TMP/cpp.sh"
  chmod +x "$TMP/cpp.sh"
  PRE=(--preprocessor "$TMP/cpp.sh")
fi
x86_64-w64-mingw32-windres "${PRE[@]}" --input-format=rc --output-format=coff -i "$TMP/cybervault.rc" -o "$ROOT/desktop/rsrc_windows_amd64.syso"
echo "$VERSION" > "$OUT/version.txt"
echo "  desktop/rsrc_windows_amd64.syso ($VERSION)"
