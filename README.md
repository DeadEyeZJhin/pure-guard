# Pure Guard

An adult-content blocker for Android phones that are **not rooted** (Android 8+), made for
people who ask for it themselves and choose an accountability partner to hold the password.

## What it does
- **Web filter** — a local DNS-only VPN: every app's lookups are checked against a built-in
  list of about 116k adult domains, then answered by CleanBrowsing's adult filter. Google,
  Bing and YouTube are forced to SafeSearch. Nothing about browsing leaves the phone.
- **Browser guard** — an accessibility service reads browser address bars and search words;
  a blocked page goes back to the Home screen.
- **Self-repair** — with one-time `WRITE_SECURE_SETTINGS`, it turns its own pieces back on
  (always-on VPN, the accessibility service) and falls back to CleanBrowsing Private DNS
  whenever the VPN is down. It comes back by itself after a restart.
- **Password** — "Unlock and remove" needs the partner's password. Pure Guard does not stop
  anyone from uninstalling it: that stays the owner's choice.

## Activating (one time)
Pure Guard needs Android's developer tools once, to grant itself the settings permission:
1. **Wireless debugging** (Android 11+, no PC): in the app, follow the steps; the pairing
   code is typed into Pure Guard's notification. After the first pairing, turning Wireless
   debugging on is enough.
2. **From another phone**: "Activate another phone" — by USB OTG cable (Android 8+) or over
   the same Wi-Fi. It installs Pure Guard on that phone and sets it up.
3. **Shizuku**, or **PC**: `out/PureGuard-setup/setup.bat` (USB debugging on).

Xiaomi / Redmi / POCO also need "USB debugging (Security settings)" (and "Install via USB"
when another phone installs it).

## Building
Windows + Git Bash, Android SDK build-tools 35 and platform 35 at `D:/AndroidBuild/sdk`, a JDK.
```bash
./build.sh            # test build (logs blocks to logcat, shows TEST)
./build.sh release    # the build that is handed out
bash test/run.sh      # PC self-tests: DNS filter, and the pairing crypto (SPAKE2, adb keys)
```
Signing uses `../valofps.keystore` with its password in `../valofps.pass` (not in this repo).

## Releasing
Bump `versionCode` (+1) and `versionName` in `app/AndroidManifest.xml`, write the bullets in
`CHANGELOG.md`, commit, push, then `python tools/release.py`. Installed apps check
`releases/latest/download/update.json` and show the update card.

## How the no-PC activation works
`Adb.java` is a small adb client. Pairing uses SPAKE2 over Ed25519 (`Spake2.java`, compatible
with BoringSSL's `spake25519`, which adbd uses), keyed by the 6-digit code plus TLS-exported
key material, then AES-128-GCM to swap public keys. After that it connects over TLS
(Wireless debugging) or USB bulk transfers with RSA auth (cable), and runs
`app/assets/setup.sh` as the shell user.
