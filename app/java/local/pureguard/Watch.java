package local.pureguard;

import android.accessibilityservice.AccessibilityService;
import android.os.Handler;
import android.os.Looper;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import java.util.List;

// Backup layer (the DNS VPN is the main one): in browser address bars, a blocked site or a porn
// search being typed sends the phone Home. Pure Guard does not guard itself: anyone may uninstall it.
public final class Watch extends AccessibilityService {
    // Address-bar view IDs (Chromium browsers, Firefox, Samsung, Opera, DuckDuckGo, Google app, in-app browsers).
    static final String[] URL_IDS = {"url_bar", "mozac_browser_toolbar_url_view", "location_bar_edit_text",
            "url_field", "omnibarTextInput", "search_box_text", "googleapp_srp_search_box_text",
            "iab_header_url", "editable_url_field"};

    private final Handler h = new Handler(Looper.getMainLooper());
    private final Runnable tick = new Runnable() {
        @Override public void run() {
            Guard.heal(Watch.this);
            h.postDelayed(this, 60_000);
        }
    };
    private long last;
    private final java.util.Map<String, Integer> misses = new java.util.HashMap<>();

    static volatile boolean alive;
    private static Watch instance;

    @Override
    protected void onServiceConnected() {
        instance = this;
        alive = true;
        h.post(tick);
    }

    @Override
    public void onAccessibilityEvent(AccessibilityEvent e) {
        if (!Guard.locked(this)) { battery(); return; } // setup: only note the Xiaomi battery choice
        // An app whose last 3 checks showed no address bar (feed, video, game) is not checked again on
        // every redraw, only when it opens a new screen: reading it 4 times a second made phones lag.
        CharSequence p = e.getPackageName();
        if (e.getEventType() == AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED && p != null
                && misses.getOrDefault(p.toString(), 0) >= 3) return;
        long now = System.currentTimeMillis();
        // Too soon after the last scan: scan once a moment later instead of dropping it, so an
        // address bar that changes during a burst of redraws is still read.
        h.removeCallbacks(scan);
        if (e.getEventType() == AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED && now - last < 250) h.postDelayed(scan, 300);
        else scan.run();
    }

    private final Runnable scan = this::scan;

    private void battery() {
        AccessibilityNodeInfo root = getRootInActiveWindow();
        if (root != null && root.getPackageName() != null && "com.miui.powerkeeper".equals(root.getPackageName().toString()))
            noRestrictions(root);
    }

    private void scan() {
        last = System.currentTimeMillis();
        AccessibilityNodeInfo root = getRootInActiveWindow();
        if (root == null || root.getPackageName() == null) return;
        String pkg = root.getPackageName().toString();
        if (pkg.equals(getPackageName())) return;
        if (pkg.equals("com.miui.powerkeeper")) { noRestrictions(root); return; }

        String url = urlText(root, pkg);
        misses.put(pkg, url == null ? misses.getOrDefault(pkg, 0) + 1 : 0);
        if (url != null && Dns.badUrl(url)) {
            log(pkg, "url", url);
            performGlobalAction(GLOBAL_ACTION_HOME); // silent: no message that names the app or says why
            return;
        }
    }

    // Test builds only: `adb logcat -s PureGuard` shows what was blocked.
    private void log(String pkg, String why, String t) {
        if (Guard.test(this)) android.util.Log.i("PureGuard", pkg + " | " + why + " | " + t.replace('\n', '|').substring(0, Math.min(400, t.length())));
    }

    // Xiaomi's own battery saver (apart from Android's) has no API; only read what the page shows,
    // so Pure Guard knows the setup step is done. The user taps "No restrictions" themselves.
    private void noRestrictions(AccessibilityNodeInfo root) {
        if (root.findAccessibilityNodeInfosByText(getString(R.string.app_name)).isEmpty()) return;
        for (AccessibilityNodeInfo n : root.findAccessibilityNodeInfosByText("No restrictions")) {
            AccessibilityNodeInfo row = n;
            while (row != null && !row.isClickable()) row = row.getParent();
            if (row != null) Guard.prefs(this).edit().putBoolean("miui_battery", checked(row, 0)).apply();
            return;
        }
    }

    private static boolean checked(AccessibilityNodeInfo n, int depth) {
        if (n == null || depth > 4) return false;
        if (n.isChecked()) return true;
        for (int i = 0; i < n.getChildCount(); i++) if (checked(n.getChild(i), depth + 1)) return true;
        return false;
    }

    private static String urlText(AccessibilityNodeInfo root, String pkg) {
        for (String id : URL_IDS) {
            List<AccessibilityNodeInfo> l = root.findAccessibilityNodeInfosByViewId(pkg + ":id/" + id);
            for (AccessibilityNodeInfo n : l) if (n.getText() != null && n.getText().length() > 0) return n.getText().toString();
        }
        // Newer Firefox draws its toolbar with Compose: the URL is the first text inside it.
        for (AccessibilityNodeInfo n : root.findAccessibilityNodeInfosByViewId(pkg + ":id/composable_toolbar")) {
            String s = firstText(n, 0);
            if (s != null) return s;
        }
        return null;
    }

    private static String firstText(AccessibilityNodeInfo n, int depth) {
        if (n == null || depth > 8) return null;
        if (n.getText() != null && n.getText().length() > 0) return n.getText().toString();
        for (int i = 0; i < n.getChildCount(); i++) {
            String s = firstText(n.getChild(i), depth + 1);
            if (s != null) return s;
        }
        return null;
    }

    @Override
    public void onInterrupt() {}

    @Override
    public void onDestroy() {
        // An old instance can be destroyed after its replacement connected: only the current one counts.
        if (instance == this) { instance = null; alive = false; }
        h.removeCallbacks(tick);
        super.onDestroy();
    }
}
