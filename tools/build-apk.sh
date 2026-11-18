#!/usr/bin/env bash
# Builds dist/CyberVault.apk: the web app in public/ inside the small native shell in android/.
#
# No Android Studio or Gradle needed. On Ubuntu/Debian (or WSL on Windows):
#   sudo apt install aapt zipalign apksigner dalvik-exchange android-sdk-platform-23 default-jdk-headless nodejs npm
#   tools/build-apk.sh
#
# Signing: the first build creates android/cybervault-release.jks (and keystore.properties
# with its password). BACK BOTH UP and never commit them: future versions must be signed
# with the same key, or phones will refuse to install them as an update.
# You can also point CYBERVAULT_KEYSTORE / CYBERVAULT_KEYSTORE_PASS at an existing key.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
ANDROID_JAR="${ANDROID_JAR:-/usr/lib/android-sdk/platforms/android-23/android.jar}"
DX="$(command -v dalvik-exchange || command -v dx || true)"
for tool in aapt zipalign apksigner javac keytool npm; do
  command -v "$tool" >/dev/null || { echo "Missing '$tool'. See the install line at the top of this script." >&2; exit 1; }
done
[ -n "$DX" ] || { echo "Missing dx (package dalvik-exchange)." >&2; exit 1; }
[ -f "$ANDROID_JAR" ] || { echo "Missing $ANDROID_JAR (package android-sdk-platform-23)." >&2; exit 1; }

PKG_DIR=io/github/tymonbitesthedust/cybervault
BUILD="$ROOT/build/android"
rm -rf "$BUILD"
mkdir -p "$BUILD/gen" "$BUILD/classes" "$BUILD/assets/www" "$ROOT/dist"

echo "› Copying the web app"
cp -R public/. "$BUILD/assets/www/"
rm -f "$BUILD/assets/www/manifest.webmanifest"

echo "› Bundling the Firebase SDK (so the app never downloads code)"
FIREBASE_VERSION="$(grep -o 'firebasejs/[0-9.]*' public/app.js | head -1 | cut -d/ -f2)"
SDK="$BUILD/assets/firebasejs/$FIREBASE_VERSION"
mkdir -p "$SDK"
( cd "$BUILD" && npm pack --silent "firebase@$FIREBASE_VERSION" >/dev/null \
  && tar -xzf "firebase-$FIREBASE_VERSION.tgz" package/firebase-app.js package/firebase-auth.js package/firebase-firestore.js \
  && mv package/*.js "$SDK/" && rm -rf package "firebase-$FIREBASE_VERSION.tgz" )
cat > "$SDK/NOTICE.txt" <<EOF
Firebase JavaScript SDK $FIREBASE_VERSION, copyright Google LLC.
Licensed under the Apache License, Version 2.0: https://www.apache.org/licenses/LICENSE-2.0
Source: https://github.com/firebase/firebase-js-sdk
EOF

echo "› Setting the version from public/app.js"
# The APK's version always matches the app's APP_VERSION (e.g. 2.0.0 → versionName 2.0.0, versionCode 20000).
APP_VERSION="$(sed -n "s/^const APP_VERSION = '\([0-9]*\.[0-9]*\.[0-9]*\)';/\1/p" public/app.js)"
[ -n "$APP_VERSION" ] || { echo "Couldn't find APP_VERSION in public/app.js" >&2; exit 1; }
IFS=. read -r V_MAJOR V_MINOR V_PATCH <<< "$APP_VERSION"
VERSION_CODE=$((V_MAJOR * 10000 + V_MINOR * 100 + V_PATCH))
MANIFEST="$BUILD/AndroidManifest.xml"
sed -e "s/android:versionCode=\"[0-9]*\"/android:versionCode=\"$VERSION_CODE\"/" \
    -e "s/android:versionName=\"[^\"]*\"/android:versionName=\"$APP_VERSION\"/" android/AndroidManifest.xml > "$MANIFEST"
echo "  $APP_VERSION (versionCode $VERSION_CODE)"

echo "› Compiling"
aapt package -f -m -J "$BUILD/gen" -M "$MANIFEST" -S android/res -I "$ANDROID_JAR"
javac -nowarn --release 8 -Xlint:-options -encoding UTF-8 -classpath "$ANDROID_JAR" -d "$BUILD/classes" \
  $(find android/src -name '*.java') "$BUILD/gen/$PKG_DIR/R.java"
"$DX" --dex --min-sdk-version=24 --output="$BUILD/classes.dex" "$BUILD/classes"

echo "› Packaging"
aapt package -f -M "$MANIFEST" -S android/res -A "$BUILD/assets" -I "$ANDROID_JAR" \
  -F "$BUILD/unsigned.apk"
( cd "$BUILD" && aapt add unsigned.apk classes.dex >/dev/null )
zipalign -f -p 4 "$BUILD/unsigned.apk" "$BUILD/aligned.apk"

echo "› Signing"
KEYSTORE="${CYBERVAULT_KEYSTORE:-android/cybervault-release.jks}"
if [ -z "${CYBERVAULT_KEYSTORE_PASS:-}" ] && [ -f android/keystore.properties ]; then
  CYBERVAULT_KEYSTORE_PASS="$(sed -n 's/^storePassword=//p' android/keystore.properties)"
fi
if [ ! -f "$KEYSTORE" ]; then
  CYBERVAULT_KEYSTORE_PASS="$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
  keytool -genkeypair -keystore "$KEYSTORE" -storepass "$CYBERVAULT_KEYSTORE_PASS" -keypass "$CYBERVAULT_KEYSTORE_PASS" \
    -alias cybervault -keyalg RSA -keysize 3072 -validity 10000 -dname "CN=CyberVault" >/dev/null 2>&1
  printf 'storeFile=%s\nstorePassword=%s\nkeyAlias=cybervault\n' "$(basename "$KEYSTORE")" "$CYBERVAULT_KEYSTORE_PASS" > android/keystore.properties
  echo "  Created a new signing key: $KEYSTORE (password in android/keystore.properties). Back both up!"
fi
apksigner sign --ks "$KEYSTORE" --ks-pass "pass:$CYBERVAULT_KEYSTORE_PASS" --ks-key-alias cybervault \
  --min-sdk-version 24 --out dist/CyberVault.apk "$BUILD/aligned.apk"
rm -f dist/CyberVault.apk.idsig
apksigner verify dist/CyberVault.apk
echo "✓ dist/CyberVault.apk, version $APP_VERSION ($(du -h dist/CyberVault.apk | cut -f1))"
