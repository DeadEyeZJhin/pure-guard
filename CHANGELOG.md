# Pure Guard — version log

Every release gets a section here, newest first. The bullets are written for the people using
the app: the phone shows them under **What's new** after an update, and the update card shows
them to phones that have not updated yet. `tools/release.py` reads one `## <version> — <date>`
heading per release, then its `- ` bullets (a bullet may wrap onto indented lines).

## 1.19 — upcoming
- **"Unlock and remove" fully lets go.** The web filter stops right away, Android's always-on
  VPN no longer restarts it, and Private DNS goes back to Android's default.
- **Xiaomi: "No restrictions" is detected.** Xiaomi manages VPN apps with its own
  "No restrictions", so that is the setting Pure Guard checks there.
- **Always-on VPN stays set** on Android 12 and newer while protected.
- **Shield bounce.** The shield on the home screen bounces when tapped.
- **Preview the home screen** from the setup screen, without locking anything.
- **Quieter wording** in Android's Accessibility settings.

## 1.18 — 2026-11-19
- **Activate without a PC or Shizuku.** Tap **Wireless debugging**, open "Pair device with
  pairing code" and type the 6 digits into Pure Guard's notification. Shizuku still works too.
- **Activates by itself next time.** Once this phone has paired, just turn Wireless debugging
  on with Pure Guard open: no code needed.
- **Clear status.** The setup screen says **ACTIVATED**, **NOT ACTIVATED** or **PROTECTED**,
  and a message tells you the moment activation is done.
- **Help another phone.** Activate a friend's phone from yours, by USB OTG cable (Android 8+)
  or over the same Wi-Fi (Android 11+). Pure Guard is installed on it and set up.
- **New look.** A clean dark design, a shield home screen with **Quick scan**, and simpler
  buttons on the setup screen.
- **Updates.** A card tells you when a new version is out, with what changed.

## 1.16 — 2026-11-15
- Blocked pages go back to the Home screen quietly, with no message.

## 1.15 — 2026-11-15
- Less battery and heat while scrolling.
