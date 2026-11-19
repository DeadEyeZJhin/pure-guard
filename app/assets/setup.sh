# Pure Guard setup. Runs as the adb "shell" user, either from setup.bat (USB, PC) or from the app
# through Shizuku (no PC). Same steps both ways. Safe to run again: every step is idempotent.
P=local.pureguard
echo "== Pure Guard setup"

# Lets the app turn its own pieces back on (accessibility, always-on VPN, private DNS) if switched off.
pm grant $P android.permission.WRITE_SECURE_SETTINGS
# VPN consent without the dialog; restricted-settings and background rules that would stop it.
appops set $P ACTIVATE_VPN allow
appops set $P ACCESS_RESTRICTED_SETTINGS allow 2>/dev/null
appops set $P RUN_ANY_IN_BACKGROUND allow 2>/dev/null
dumpsys deviceidle whitelist +$P >/dev/null 2>&1
# Xiaomi/Redmi/POCO Autostart (MIUI app op 10008); other phones reject the unknown op, ignored.
# Xiaomi's battery saver "No restrictions" has no shell switch: the user taps it in the app.
appops set $P 10008 allow 2>/dev/null
# Android starts an always-on VPN by itself at every boot. No lockdown: this VPN only carries DNS.
settings put secure always_on_vpn_app $P
settings put secure always_on_vpn_lockdown 0
s=$(settings get secure enabled_accessibility_services)
case "$s" in
  *"$P/"*) ;;
  null|"") settings put secure enabled_accessibility_services $P/.Watch ;;
  *) settings put secure enabled_accessibility_services "$s:$P/.Watch" ;;
esac
settings put secure accessibility_enabled 1
am start -n $P/.Main --ez setup true >/dev/null 2>&1

echo "Next, on the phone: create the unlock password and give it to the accountability partner."
echo "SETUP-OK"
