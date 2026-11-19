package local.pureguard;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.provider.Settings;
import java.security.MessageDigest;
import java.security.SecureRandom;

// The lock itself: what "protected" means on this phone, how it heals, and how the password removes it.
final class Guard {
    static final String DOT_HOST = "adult-filter-dns.cleanbrowsing.org"; // Private DNS while the VPN is down

    private Guard() {}

    static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences("guard", Context.MODE_PRIVATE);
    }

    static ComponentName admin(Context c) {
        return new ComponentName(c, Admin.class);
    }

    static DevicePolicyManager dpm(Context c) {
        return (DevicePolicyManager) c.getSystemService(Context.DEVICE_POLICY_SERVICE);
    }

    static boolean canHeal(Context c) {
        return c.checkSelfPermission("android.permission.WRITE_SECURE_SETTINGS") == PackageManager.PERMISSION_GRANTED;
    }

    // Set up = setup.sh ran (it grants the settings permission).
    static boolean setUp(Context c) {
        return canHeal(c);
    }

    // Locked = a password exists. Nothing is enforced before that, so nobody gets trapped without one.
    static boolean locked(Context c) {
        return prefs(c).contains("pw");
    }

    // Test builds (assets/test-mode, the default of build.sh) log what Watch blocks.
    private static Boolean test;

    static boolean test(Context c) {
        if (test == null) {
            try { c.getAssets().open("test-mode").close(); test = true; } catch (Exception e) { test = false; }
        }
        return test;
    }

    static void lock(Context c, String password) {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        String s = hex(salt);
        prefs(c).edit().putString("salt", s).putString("pw", hash(s, password)).commit();
        apply(c);
    }

    static boolean check(Context c, String password) {
        SharedPreferences p = prefs(c);
        return p.contains("pw") && hash(p.getString("salt", ""), password).equals(p.getString("pw", ""));
    }

    static void apply(Context c) {
        if (!locked(c)) return;
        heal(c);
    }

    // Puts back whatever was switched off. Runs at boot, every minute from the VPN and from Watch.
    static void heal(Context c) {
        releaseAdmin(c);
        ContentResolver cr = c.getContentResolver();
        String me = c.getPackageName();
        if (!locked(c)) return;
        if (canHeal(c)) try {
            String w = me + "/.Watch";
            String s = Settings.Secure.getString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
            if (s != null && s.contains(me + "/") && !Watch.alive) {
                // Listed but not running (e.g. after the app was disabled and enabled): rewrite to rebind.
                s = s.replaceAll(":?" + java.util.regex.Pattern.quote(me) + "/[^:]*", "").replaceAll("^:", "");
                Settings.Secure.putString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES, s);
            }
            if (s == null || !s.contains(me + "/")) {
                Settings.Secure.putString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
                        s == null || s.isEmpty() ? w : s + ":" + w);
                Settings.Secure.putString(cr, Settings.Secure.ACCESSIBILITY_ENABLED, "1");
            }
            if (!me.equals(alwaysOn(cr))) { // unreadable on Android 12+: the write is then a no-op when unchanged
                Settings.Secure.putString(cr, "always_on_vpn_app", me);
                Settings.Secure.putString(cr, "always_on_vpn_lockdown", "0");
            }
        } catch (Exception ignored) {}
        if (!Vpn.running && VpnService.prepare(c) == null) {
            try { c.startService(new Intent(c, Vpn.class)); } catch (Exception ignored) {}
        }
        if (!Vpn.running) vpnDown(c);
    }

    // Private DNS would bypass the VPN's own DNS, so it is off while the VPN runs, and set to
    // CleanBrowsing's filter whenever the VPN is down (killed, crashed, not started yet).
    static void vpnUp(Context c) {
        putGlobal(c, "private_dns_mode", "off");
    }

    static void vpnDown(Context c) {
        if (!locked(c)) return;
        putGlobal(c, "private_dns_specifier", DOT_HOST);
        putGlobal(c, "private_dns_mode", "hostname");
    }

    private static void putGlobal(Context c, String k, String v) {
        if (!canHeal(c)) return;
        try { Settings.Global.putString(c.getContentResolver(), k, v); } catch (Exception ignored) {}
    }

    // Correct password: everything goes back to normal and the app becomes uninstallable.
    static void unlock(Context c) {
        prefs(c).edit().clear().commit();
        ContentResolver cr = c.getContentResolver();
        String me = c.getPackageName();
        if (canHeal(c)) try {
            String s = Settings.Secure.getString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
            if (s != null) Settings.Secure.putString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
                    s.replaceAll(":?" + java.util.regex.Pattern.quote(me) + "/[^:]*", "").replaceAll("^:", ""));
            releaseAlwaysOn(c);
            Settings.Global.putString(cr, "private_dns_mode", "opportunistic"); // Android's default
        } catch (Exception ignored) {}
        // Vpn sees it is unlocked and closes its tunnel (stopService cannot end an established VPN).
        try { c.startService(new Intent(c, Vpn.class)); } catch (Exception e) { c.stopService(new Intent(c, Vpn.class)); }
    }

    // Android 12+ lets normal apps write always_on_vpn_app but not read it: null then.
    static String alwaysOn(ContentResolver cr) {
        try { return Settings.Secure.getString(cr, "always_on_vpn_app"); } catch (Exception e) { return null; }
    }

    // Only called when unlocked, where Pure Guard was the always-on VPN (it set itself there while locked).
    static void releaseAlwaysOn(Context c) {
        ContentResolver cr = c.getContentResolver();
        String a = alwaysOn(cr);
        if (!canHeal(c) || a != null && !a.equals(c.getPackageName())) return;
        try { Settings.Secure.putString(cr, "always_on_vpn_app", ""); } catch (Exception ignored) {}
    }

    // Older test builds made Pure Guard a device admin or owner, which blocks uninstalling it.
    // Pure Guard no longer stops anyone from uninstalling it: let go of both.
    private static void releaseAdmin(Context c) {
        DevicePolicyManager d = dpm(c);
        try { if (d.isDeviceOwnerApp(c.getPackageName())) d.clearDeviceOwnerApp(c.getPackageName()); } catch (Exception ignored) {}
        try { if (d.isAdminActive(admin(c))) d.removeActiveAdmin(admin(c)); } catch (Exception ignored) {}
    }

    private static String hash(String salt, String pw) {
        try {
            return hex(MessageDigest.getInstance("SHA-256").digest((salt + pw).getBytes("UTF-8")));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }
}
