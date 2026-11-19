package local.pureguard;

import android.content.Context;
import android.content.SharedPreferences;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import org.json.JSONObject;

// Update check, same scheme as Winter Air: tools/release.py puts update.json on each GitHub
// release, and /releases/latest/download/ always points at the newest one. Only that file is
// fetched; nothing about the phone is sent. "What's new" comes from assets/whatsnew.txt.
final class Update {
    static final String URL = "https://github.com/DeadEyeZJhin/pure-guard/releases/latest/download/update.json";
    private static final long EVERY = 6 * 3600_000L;

    private Update() {}

    // Kept apart from Guard's prefs, which "Unlock and remove" clears.
    static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences("app", Context.MODE_PRIVATE);
    }

    @SuppressWarnings("deprecation")
    static int myCode(Context c) {
        try { return c.getPackageManager().getPackageInfo(c.getPackageName(), 0).versionCode; } catch (Exception e) { return 0; }
    }

    // The cached newer release, or null.
    static JSONObject newer(Context c) {
        try {
            JSONObject j = new JSONObject(prefs(c).getString("upd", "{}"));
            return j.optInt("versionCode") > myCode(c) && j.optString("apkUrl").startsWith("https://github.com/") ? j : null;
        } catch (Exception e) {
            return null;
        }
    }

    // Fetches update.json at most every 6 hours, then runs `done` (on the calling thread's side: post it).
    static void refresh(Context c, Runnable done) {
        SharedPreferences p = prefs(c);
        if (System.currentTimeMillis() - p.getLong("upd_at", 0) < EVERY) return;
        p.edit().putLong("upd_at", System.currentTimeMillis()).apply();
        new Thread(() -> {
            try {
                HttpURLConnection h = (HttpURLConnection) new URL(URL).openConnection();
                h.setConnectTimeout(10000);
                h.setReadTimeout(10000);
                if (h.getResponseCode() != 200) return;
                try (InputStream in = h.getInputStream()) {
                    String s = new String(Adb.readAll(in), "UTF-8");
                    new JSONObject(s); // only valid JSON is kept
                    p.edit().putString("upd", s).apply();
                }
                done.run();
            } catch (Exception ignored) {} // offline: try again next time
        }).start();
    }

    // This version's notes, shown once after an update.
    static String whatsNew(Context c) {
        try (InputStream in = c.getAssets().open("whatsnew.txt")) {
            return new String(Adb.readAll(in), "UTF-8").trim();
        } catch (Exception e) {
            return "";
        }
    }
}
