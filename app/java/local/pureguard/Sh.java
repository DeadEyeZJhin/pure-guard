package local.pureguard;

import android.content.pm.PackageManager;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import rikka.shizuku.Shizuku;

// Runs shell scripts as the adb "shell" user through Shizuku: no root on this phone, but shell
// may force-stop, freeze (pm disable-user) and change global settings. Call off the main thread.
final class Sh {
    static final int REQ = 7;

    private Sh() {}

    // Why the app can't use Shizuku right now, or null when it can.
    static String problem(android.content.Context c) {
        try {
            c.getPackageManager().getPackageInfo("moe.shizuku.privileged.api", 0);
        } catch (PackageManager.NameNotFoundException e) {
            return "Shizuku is not installed. Install it from the Play Store.";
        }
        if (!Shizuku.pingBinder()) return "Shizuku is not running. Open Shizuku and tap Start (Wireless debugging). Setup needs it only once.";
        if (Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) return "Pure Guard needs Shizuku permission: tap Allow.";
        return null;
    }

    // Script output (stdout + stderr), or null when Shizuku is not usable.
    static String run(String script) {
        try {
            // A cold start (tile, shortcut) gets Shizuku's binder a moment after the process starts.
            for (int i = 0; i < 20 && !Shizuku.pingBinder(); i++) Thread.sleep(100);
            if (!Shizuku.pingBinder() ||Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) return null;
            // shortcut: newProcess is private since Shizuku API 13 (it wants a bound UserService);
            // reflection still works on 13.x, move to UserService if a later Shizuku breaks it.
            Method m = Shizuku.class.getDeclaredMethod("newProcess", String[].class, String[].class, String.class);
            m.setAccessible(true);
            Process p = (Process) m.invoke(null, new String[]{"sh"}, null, null);
            try (OutputStream in = p.getOutputStream()) {
                in.write(("exec 2>&1\n" + script + "\n").getBytes("UTF-8"));
            }
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            try (InputStream out = p.getInputStream()) {
                byte[] buf = new byte[8192];
                for (int n; (n = out.read(buf)) > 0; ) b.write(buf, 0, n);
            }
            p.waitFor();
            return b.toString("UTF-8");
        } catch (Throwable e) {
            return null;
        }
    }
}
