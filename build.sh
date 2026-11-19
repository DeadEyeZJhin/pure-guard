#!/bin/bash
# Builds Pure Guard (out/PureGuard.apk) and the PC setup folder (out/PureGuard-setup/).
# blocklist.txt (about 116k names, one per line) lives in the repo. When the tablet lock's list
# (../netcfg/payload/block.txt) is next door, it is refreshed from there first.
# Shizuku API jars in libs/ come from Phone Boost (dev.rikka.shizuku 13.1.5).
# Signing: ../valofps.keystore, password in ../valofps.pass (both outside the repo).
set -e
cd "$(dirname "$0")"
SDK=$(cygpath -m /d/AndroidBuild/sdk); BT=$SDK/build-tools/35.0.0; JAR=$SDK/platforms/android-35/android.jar
LIBS=$(ls libs/shizuku-*.jar | tr '\n' ';')
mkdir -p out && find out -mindepth 1 -delete 2>/dev/null; mkdir -p out/cls out/dex out/assets  # folder may be open in Explorer
cp app/assets/* out/assets/
[ -f ../netcfg/payload/block.txt ] && sed -n 's/^0\.0\.0\.0 //p' ../netcfg/payload/block.txt > blocklist.txt
cp blocklist.txt out/assets/block.txt
python tools/release.py --notes > out/assets/whatsnew.txt  # "What's new" after an update
# Test build (default): USB debugging is never blocked. `./build.sh release` for phones handed out.
if [ "$1" = release ]; then MODE=RELEASE; else MODE=TEST; echo test > out/assets/test-mode; fi
"$BT/aapt2.exe" compile --dir app/res -o out/res.zip
"$BT/aapt2.exe" link -o out/base.apk --manifest app/AndroidManifest.xml -I "$JAR" \
  --min-sdk-version 26 --target-sdk-version 34 -A out/assets --java out/gen out/res.zip
javac --release 8 -encoding UTF-8 -nowarn -cp "$JAR;$LIBS" -d out/cls $(find app/java out/gen -name '*.java')
"$BT/d8.bat" --release --min-api 26 --lib "$JAR" --output out/dex $(find out/cls -name '*.class') libs/shizuku-*.jar
(cd out/dex && jar uf ../base.apk classes.dex)
"$BT/zipalign.exe" -f -P 16 4 out/base.apk out/aligned.apk
"$BT/apksigner.bat" sign --ks ../valofps.keystore --ks-pass file:../valofps.pass --out out/PureGuard.apk out/aligned.apk
S=out/PureGuard-setup; mkdir -p $S/adb
cp out/PureGuard.apk app/assets/setup.sh setup/setup.bat setup/README.txt $S/
PT=$(dirname "$(which adb)"); cp "$PT"/{adb.exe,AdbWinApi.dll,AdbWinUsbApi.dll,libwinpthread-1.dll,NOTICE.txt} $S/adb/ 2>/dev/null || cp "$PT"/{adb.exe,AdbWinApi.dll,AdbWinUsbApi.dll,NOTICE.txt} $S/adb/
echo "built $MODE out/PureGuard.apk and $S/"
