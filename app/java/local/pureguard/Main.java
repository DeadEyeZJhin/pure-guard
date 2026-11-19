package local.pureguard;

import android.animation.ValueAnimator;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbInterface;
import android.hardware.usb.UsbManager;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.provider.Settings;
import android.text.InputType;
import android.text.format.DateUtils;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import rikka.shizuku.Shizuku;

// Two screens. Home (what the phone's user sees once locked): a security-app dashboard with a
// shield ring, four shield tiles and Quick scan; 10 quick taps on the shield open the second one.
// Core: activation (this phone or another), the steps before the password, status and unlock.
public final class Main extends Activity {
    static final int BG = 0xFF0B1220, CARD = 0xFF141D2E, CARD2 = 0xFF1E2A3F, TEXT = 0xFFE6EDF7, SUB = 0xFF8FA3BF,
            GREEN = 0xFF22C55E, AMBER = 0xFFF59E0B, RED = 0xFFEF4444, ON_GREEN = 0xFF052E16;
    private static final String USB_ACTION = "local.pureguard.USB";

    private final Handler ui = new Handler(Looper.getMainLooper());
    private LinearLayout box, cur;
    private String log = "";
    private int wrong;
    private long waitUntil;
    private boolean details; // core screen open (after 10 taps on the shield)
    private boolean pairing, helpWifi, busy, scanning;
    private int taps;
    private long firstTap;
    private Ring ring;
    private TextView frontTitle, frontSub;
    private final Shizuku.OnRequestPermissionResultListener onPerm = (code, result) -> ui.post(this::shizukuSetup);
    // Wireless debugging switched on while Pure Guard is open: try to activate with no code.
    private final android.database.ContentObserver adbWatch = new android.database.ContentObserver(ui) {
        @Override public void onChange(boolean self) { autoActivate(); }
    };
    private final BroadcastReceiver usbPerm = new BroadcastReceiver() {
        @Override public void onReceive(Context c, Intent i) {
            if (i.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)) cable();
            else say("USB permission was not given.");
        }
    };

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        ScrollView sv = new ScrollView(this);
        sv.setBackgroundColor(BG);
        sv.setFillViewport(true);
        box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(18), dp(20), dp(18), dp(28));
        sv.addView(box);
        setContentView(sv);
        Shizuku.addRequestPermissionResultListener(onPerm);
        IntentFilter f = new IntentFilter(USB_ACTION);
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(usbPerm, f, Context.RECEIVER_NOT_EXPORTED);
        else registerReceiver(usbPerm, f);
        getContentResolver().registerContentObserver(Settings.Global.getUriFor("adb_wifi_enabled"), false, adbWatch);
    }

    @Override
    protected void onDestroy() {
        Shizuku.removeRequestPermissionResultListener(onPerm);
        unregisterReceiver(usbPerm);
        getContentResolver().unregisterContentObserver(adbWatch);
        super.onDestroy();
    }

    @Override
    protected void onResume() {
        super.onResume();
        Guard.heal(this);
        if (Guard.setUp(this)) { pairing = false; Activate.cancel(this); }
        refresh();
        Update.refresh(this, () -> ui.post(this::refresh));
        popups();
        autoActivate();
    }

    // "Activated ✓" once after activation; "What's new" once after an update (not on the disguised home).
    private void popups() {
        boolean locked = Guard.locked(this);
        if (!locked && Guard.setUp(this) && !Guard.prefs(this).getBoolean("act_seen", false)) {
            Guard.prefs(this).edit().putBoolean("act_seen", true).apply();
            new AlertDialog.Builder(this).setTitle("Activated ✓")
                    .setMessage("This phone is activated. Next: finish the steps on this screen, then create the unlock password.")
                    .setPositiveButton("OK", null).show();
            return;
        }
        android.content.SharedPreferences a = Update.prefs(this);
        int me = Update.myCode(this), seen = a.getInt("seen", 0);
        if (seen >= me) return;
        a.edit().putInt("seen", me).apply();
        String notes = Update.whatsNew(this);
        if (seen > 0 && !notes.isEmpty() && !locked)
            new AlertDialog.Builder(this).setTitle("What's new").setMessage(notes).setPositiveButton("OK", null).show();
    }

    // Not activated, paired before, Wireless debugging on: activate without asking for a code.
    private void autoActivate() {
        if (busy || Guard.setUp(this) || Build.VERSION.SDK_INT < 30 || !Update.prefs(this).getBoolean("self_paired", false)
                || Settings.Global.getInt(getContentResolver(), "adb_wifi_enabled", 0) != 1) return;
        work(s -> {
            String r = Activate.selfAuto(this, s);
            return Activate.NEED_CODE.equals(r) ? "Wireless debugging is on, but this phone is not paired yet: "
                    + "tap \"Wireless debugging · no PC\" and use the pairing code once." : r;
        }, "Activated ✓");
    }

    @Override
    protected void onStop() {
        super.onStop();
        if (ring != null) ring.spin(false);
        if (Guard.locked(this)) details = false; // leaving the app always returns to the home screen
    }

    @Override
    public void onBackPressed() {
        if (details && Guard.locked(this)) { details = false; refresh(); }
        else super.onBackPressed();
    }

    private void refresh() {
        if (scanning) return;
        box.removeAllViews();
        cur = box;
        ring = null;
        if (Guard.locked(this) && !details) front();
        else core();
    }

    // ================= Home =================

    private void front() {
        boolean web = Vpn.running, browser = watchOn() && Watch.alive, heal = Guard.canHeal(this), bg = battery();
        int bad = (web ? 0 : 1) + (browser ? 0 : 1) + (heal ? 0 : 1) + (bg ? 0 : 1);
        int accent = bad == 0 ? GREEN : AMBER;

        TextView brand = text("PURE GUARD", 13, SUB);
        brand.setLetterSpacing(0.25f);
        brand.setGravity(Gravity.CENTER);

        FrameLayout hero = new FrameLayout(this);
        ring = new Ring(this, accent);
        hero.addView(ring, new FrameLayout.LayoutParams(-1, -1));
        ImageView shield = new ImageView(this);
        shield.setImageResource(bad == 0 ? R.drawable.shield_big : R.drawable.shield_warn);
        FrameLayout.LayoutParams sp = new FrameLayout.LayoutParams(dp(110), dp(110), Gravity.CENTER);
        hero.addView(shield, sp);
        LinearLayout.LayoutParams hp = new LinearLayout.LayoutParams(dp(250), dp(250));
        hp.gravity = Gravity.CENTER_HORIZONTAL;
        hp.topMargin = dp(18);
        hp.bottomMargin = dp(10);
        box.addView(hero, hp);
        View.OnClickListener secret = v -> {
            long now = android.os.SystemClock.uptimeMillis();
            if (now - firstTap > 4000) { firstTap = now; taps = 0; }
            if (++taps >= 10) { taps = 0; details = true; refresh(); }
        };
        shield.setOnClickListener(secret);
        ring.spin(true);

        frontTitle = text(bad == 0 ? "You're protected" : !web ? "Starting protection…" : "Needs attention", 28, TEXT);
        frontTitle.setTypeface(Typeface.DEFAULT_BOLD);
        frontTitle.setGravity(Gravity.CENTER);
        long last = Guard.prefs(this).getLong("scan", 0);
        frontSub = text((bad == 0 ? "All shields are active" : bad + (bad == 1 ? " shield needs" : " shields need") + " attention")
                + (last <= 0 ? "" : System.currentTimeMillis() - last < 60_000 ? "  ·  Scanned just now"
                : "  ·  Scanned " + DateUtils.getRelativeTimeSpanString(last, System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS)), 14, SUB);
        frontSub.setGravity(Gravity.CENTER);
        space(16);

        LinearLayout r1 = rowBox(), r2 = rowBox();
        tile(r1, "Web Shield", web);
        tile(r1, "Browser Shield", browser);
        tile(r2, "Auto-Repair", heal);
        tile(r2, "Always On", bg);
        space(18);
        button("Quick scan", GREEN, ON_GREEN, this::scan);
        org.json.JSONObject u = Update.newer(this);
        if (u != null) button("Update available  ·  " + u.optString("versionName"), CARD2, TEXT, () -> download(u));
    }

    private void download(org.json.JSONObject u) {
        open(new Intent(Intent.ACTION_VIEW, Uri.parse(u.optString("apkUrl"))));
    }

    // Real checks (the four tiles) dressed as a scan; Guard.heal fixes what it can first.
    private void scan() {
        if (scanning || ring == null) return;
        scanning = true;
        Guard.heal(this);
        String[] steps = {"Checking web shield…", "Checking browser shield…", "Checking auto-repair…", "Checking background protection…"};
        frontTitle.setText("Scanning…");
        ring.spin(false);
        ValueAnimator a = ValueAnimator.ofFloat(0f, 1f).setDuration(2800);
        a.addUpdateListener(v -> {
            float f = (float) v.getAnimatedValue();
            ring.progress(f);
            frontTitle.setText("Scanning… " + (int) (f * 100) + "%");
            frontSub.setText(steps[Math.min(steps.length - 1, (int) (f * steps.length))]);
        });
        a.addListener(new android.animation.AnimatorListenerAdapter() {
            @Override public void onAnimationEnd(android.animation.Animator x) {
                scanning = false;
                Guard.prefs(Main.this).edit().putLong("scan", System.currentTimeMillis()).apply();
                refresh();
                boolean ok = Vpn.running && watchOn() && Watch.alive && Guard.canHeal(Main.this) && battery();
                toast(ok ? "Scan complete: no problems found" : "Scan complete: some shields need attention");
            }
        });
        a.start();
    }

    private void tile(LinearLayout row, String name, boolean on) {
        LinearLayout t = new LinearLayout(this);
        t.setOrientation(LinearLayout.VERTICAL);
        t.setPadding(dp(14), dp(14), dp(14), dp(14));
        t.setBackground(round(CARD, 18));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, -2, 1);
        lp.setMargins(dp(5), 0, dp(5), 0);
        row.addView(t, lp);
        LinearLayout top = new LinearLayout(this);
        top.setGravity(Gravity.CENTER_VERTICAL);
        View dot = new View(this);
        dot.setBackground(oval(on ? GREEN : AMBER));
        top.addView(dot, new LinearLayout.LayoutParams(dp(9), dp(9)));
        TextView s = new TextView(this);
        s.setText(on ? "  Active" : "  Off");
        s.setTextColor(on ? GREEN : AMBER);
        s.setTextSize(12);
        top.addView(s);
        t.addView(top);
        TextView n = new TextView(this);
        n.setText(name);
        n.setTextColor(TEXT);
        n.setTextSize(15);
        n.setTypeface(Typeface.DEFAULT_BOLD);
        n.setPadding(0, dp(8), 0, 0);
        t.addView(n);
    }

    private LinearLayout rowBox() {
        LinearLayout r = new LinearLayout(this);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.bottomMargin = dp(10);
        lp.leftMargin = lp.rightMargin = -dp(5);
        box.addView(r, lp);
        return r;
    }

    // The ring around the shield: a slow sweeping highlight when idle, a progress arc while scanning.
    static final class Ring extends View {
        private final Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final int color;
        private float prog = 1f, angle;
        private ValueAnimator spin;

        Ring(Context c, int color) {
            super(c);
            this.color = color;
            p.setStrokeCap(Paint.Cap.ROUND);
        }

        void spin(boolean on) {
            if (spin != null) { spin.cancel(); spin = null; }
            if (!on) return;
            prog = 1f;
            spin = ValueAnimator.ofFloat(0, 360).setDuration(5000);
            spin.setRepeatCount(ValueAnimator.INFINITE);
            spin.setInterpolator(new android.view.animation.LinearInterpolator());
            spin.addUpdateListener(v -> { angle = (float) v.getAnimatedValue(); invalidate(); });
            spin.start();
        }

        void progress(float f) { prog = f; invalidate(); }

        @Override protected void onDetachedFromWindow() { spin(false); super.onDetachedFromWindow(); }

        @Override protected void onDraw(Canvas c) {
            float d = getResources().getDisplayMetrics().density, w = 10 * d;
            float cx = getWidth() / 2f, cy = getHeight() / 2f, r = Math.min(cx, cy) - w;
            p.setStyle(Paint.Style.FILL);
            p.setColor((color & 0xFFFFFF) | 0x14000000);
            c.drawCircle(cx, cy, r * 0.82f, p);
            p.setColor((color & 0xFFFFFF) | 0x0C000000);
            c.drawCircle(cx, cy, r * 0.62f, p);
            p.setStyle(Paint.Style.STROKE);
            p.setStrokeWidth(w);
            RectF o = new RectF(cx - r, cy - r, cx + r, cy + r);
            p.setColor(CARD2);
            c.drawArc(o, 0, 360, false, p);
            p.setColor(color);
            c.drawArc(o, -90, 360 * prog, false, p);
            if (spin != null) {
                p.setColor(0x99FFFFFF);
                c.drawArc(o, angle - 90, 34, false, p);
            }
        }
    }

    // ================= Core =================

    private void core() {
        boolean locked = Guard.locked(this);
        LinearLayout head = new LinearLayout(this);
        head.setGravity(Gravity.CENTER_VERTICAL);
        box.addView(head);
        LinearLayout titles = new LinearLayout(this);
        titles.setOrientation(LinearLayout.VERTICAL);
        head.addView(titles, new LinearLayout.LayoutParams(0, -2, 1));
        cur = titles;
        TextView t = text("Pure Guard", 26, TEXT);
        t.setTypeface(Typeface.DEFAULT_BOLD);
        // Big, plain answer to "is this phone activated?"
        boolean act = Guard.setUp(this);
        int pc = locked || act ? GREEN : AMBER;
        TextView pill = new TextView(this);
        pill.setText(locked ? "●  PROTECTED" : act ? "●  ACTIVATED" : "●  NOT ACTIVATED");
        pill.setTextColor(pc);
        pill.setTextSize(13);
        pill.setTypeface(Typeface.DEFAULT_BOLD);
        pill.setLetterSpacing(0.06f);
        pill.setBackground(round((pc & 0xFFFFFF) | 0x26000000, 12));
        pill.setPadding(dp(12), dp(6), dp(12), dp(6));
        LinearLayout.LayoutParams pl = new LinearLayout.LayoutParams(-2, -2);
        pl.topMargin = dp(6);
        titles.addView(pill, pl);
        if (Guard.test(this)) {
            cur = head;
            TextView chip = text("TEST", 11, AMBER);
            chip.setTypeface(Typeface.DEFAULT_BOLD);
            chip.setBackground(round(0x33F59E0B, 10));
            chip.setPadding(dp(10), dp(4), dp(10), dp(4));
        }
        cur = box;
        space(14);

        org.json.JSONObject u = Update.newer(this);
        if (u != null) {
            section("Update available: " + u.optString("versionName"));
            org.json.JSONArray n = u.optJSONArray("notes");
            for (int i = 0; n != null && i < n.length(); i++) para("• " + n.optString(i).replace("**", ""));
            button("Download the update", GREEN, ON_GREEN, () -> download(u));
            para("Install it over this one: protection and the password stay.");
        }

        if (!locked && !Guard.setUp(this)) activateThis();
        else if (!locked) beforeLock();
        else status();
        helpOthers();
        if (!log.isEmpty()) {
            section("Activity");
            TextView l = text(log, 12, SUB);
            l.setTypeface(Typeface.MONOSPACE);
            l.setTextIsSelectable(true);
        }
        cur = box;
        if (locked) { space(6); flat("‹ Back to home", () -> { details = false; refresh(); }); }
    }

    private void activateThis() {
        section("Activate this phone");
        para("Pure Guard needs a one-time permission from Android's developer tools. Nothing is sent anywhere.");
        if (pairing) {
            if (Build.VERSION.SDK_INT < 30) {
                para("This phone is Android " + Build.VERSION.RELEASE + ": it has no Wireless debugging. "
                        + "Use another phone's \"By cable\" button below, or setup.bat on a PC.");
            } else {
                step(1, "Connect this phone to Wi-Fi.");
                step(2, "Turn on Developer options: Settings › About phone › tap \"Build number\" 7 times.");
                button("Open Developer options", CARD2, TEXT, () -> open(new Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)));
                step(3, "Turn on Wireless debugging, then tap \"Pair device with pairing code\".");
                step(4, "Keep that popup open. Pull down the notifications, tap \"Enter pairing code\" on Pure Guard's, and type the 6 digits.");
                if (xiaomi()) para("Xiaomi: also turn on \"USB debugging (Security settings)\" in Developer options.");
                String st = Guard.prefs(this).getString("act", "");
                if (!st.isEmpty()) note(st);
                button("Show the code box again", CARD2, TEXT, () -> Activate.notify(this, "Waiting for the pairing code…", true));
            }
        } else {
            button("Wireless debugging  ·  no PC", GREEN, ON_GREEN, this::startPairing);
            button("Shizuku", CARD2, TEXT, this::shizukuSetup);
            para("Have a PC? Plug this phone in and run setup.bat.");
        }
    }

    private void startPairing() {
        pairing = true;
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != 0)
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 2);
        if (Build.VERSION.SDK_INT >= 30) {
            Activate.notify(this, "Waiting for the pairing code…", true);
            new Thread(() -> { try { Adb.key(this); } catch (Exception ignored) {} }).start(); // RSA key ready before the code
        }
        refresh();
        autoActivate(); // paired before and Wireless debugging already on: no code needed
    }

    @Override
    public void onRequestPermissionsResult(int req, String[] p, int[] r) {
        if (req == 2 && pairing) Activate.notify(this, "Waiting for the pairing code…", true);
    }

    private void beforeLock() {
        // Without these, Xiaomi stops Pure Guard in the background or after a restart.
        boolean nr = !xiaomi() || Guard.prefs(this).getBoolean("miui_battery", false), auto = !xiaomi() || autostartOn();
        boolean idle = battery(); // setup adds this, but Xiaomi clears it once shortly after an install
        section("Before you lock");
        text("✓ This phone is activated. Finish these, then create the password.", 14, GREEN);
        check("Setup permission", true, null, null);
        if (xiaomi()) {
            check("Xiaomi battery saver: No restrictions", nr, "Open", this::xiaomiBattery);
            check("Xiaomi Autostart", auto, "Open", this::autostart);
        }
        check("Run in the background", idle, "Allow", this::batteryDialog);

        section("Unlock password");
        para("Give it to the accountability partner, not to the phone's user. It is needed to turn protection off.");
        EditText a = field("Password (6+ characters)", true), c = field("Type it again", true);
        button("Turn on protection", GREEN, ON_GREEN, () -> {
            String s = a.getText().toString();
            if (!nr || !auto || !idle) { toast("Finish the steps above first."); return; }
            if (s.length() < 6) { toast("At least 6 characters."); return; }
            if (!s.equals(c.getText().toString())) { toast("The two passwords are different."); return; }
            Guard.lock(this, s);
            startVpn();
            details = false;
            refresh();
        });
    }

    private void status() {
        section("Protection");
        check("Web filter", Vpn.running, null, null);
        check("Browser guard", watchOn() && Watch.alive, null, null);
        if (!Watch.alive)
            para("If it stays off: Settings › Apps › Pure Guard › ⋮ › \"Allow restricted settings\", then turn Pure Guard "
                    + "on in Settings › Accessibility. (Android blocks it after an update installed from a file.)");
        check("Self-repair permission", Guard.canHeal(this), null, null);
        if (!Guard.canHeal(this)) para("Run setup again (Wireless debugging, Shizuku or setup.bat) after unlocking.");
        check("Run in the background", battery(), "Allow", this::batteryDialog);
        if (xiaomi()) {
            check("Xiaomi battery saver", Guard.prefs(this).getBoolean("miui_battery", false), "Open", this::xiaomiBattery);
            check("Xiaomi Autostart", autostartOn(), "Open", this::autostart);
        }

        section("Partner");
        EditText pw = field("Unlock password", true);
        button("Unlock and remove", RED, 0xFFFFFFFF, () -> {
            if (!passwordOk(pw)) return;
            new AlertDialog.Builder(this).setTitle("Remove all protection?")
                    .setMessage("The web filter and the browser guard will be turned off.")
                    .setNegativeButton("Cancel", null)
                    .setPositiveButton("Remove", (d, w) -> {
                        Guard.unlock(this);
                        log = "Protection removed.";
                        refresh();
                    }).show();
        });
    }

    private void helpOthers() {
        section("Activate another phone");
        para("Installs Pure Guard on a friend's phone and sets it up from here.");
        button("By cable (USB OTG)", CARD2, TEXT, this::cable);
        para("Other phone: Developer options › USB debugging on (Xiaomi: also \"Install via USB\" and \"USB debugging "
                + "(Security settings)\"). Plug it in, then tap Allow on it. Android 8 and newer.");
        if (!helpWifi) {
            button("By Wi-Fi (same network)", CARD2, TEXT, () -> { helpWifi = true; refresh(); });
        } else if (Build.VERSION.SDK_INT < 29) {
            para("Wi-Fi activation needs this phone on Android 10 or newer. Use the cable.");
        } else {
            step(1, "Both phones on the same Wi-Fi.");
            step(2, "Other phone (Android 11+): Developer options › Wireless debugging › \"Pair device with pairing code\".");
            step(3, "Type the 6-digit code it shows (leave it empty if these two phones paired before):");
            EditText code = field("Pairing code", false);
            code.setInputType(InputType.TYPE_CLASS_NUMBER);
            EditText addr = field("IP address & port (only if not found)", false);
            button("Pair and activate", GREEN, ON_GREEN, () -> {
                String cd = code.getText().toString().trim(), ad = addr.getText().toString();
                if (!cd.isEmpty() && cd.length() != 6) { toast("The code has 6 digits."); return; }
                work(s -> Activate.wifi(this, cd, ad, s), OTHER_DONE);
            });
        }
        button("Share the app file", CARD2, TEXT, this::share);
    }

    private static final String OTHER_DONE = "Done ✓ The other phone opens Pure Guard: finish there (Xiaomi steps, then the password).";

    // Runs one activation off the main thread, showing its steps in the Activity card.
    private void work(java.util.function.Function<java.util.function.Consumer<String>, String> job, String okText) {
        if (busy) { toast("Already working…"); return; }
        busy = true;
        say("Starting…");
        new Thread(() -> {
            String err = job.apply(this::say);
            busy = false;
            say(err == null ? okText : err);
        }).start();
    }

    private void say(String s) {
        ui.post(() -> { log = s; refresh(); });
    }

    // USB OTG: this phone is the host. Asks for USB permission once, then installs and runs setup.
    private void cable() {
        UsbManager um = (UsbManager) getSystemService(USB_SERVICE);
        UsbDevice dev = null;
        for (UsbDevice d : um.getDeviceList().values()) if (Adb.adbInterface(d) != null) dev = d;
        if (dev == null) {
            say("No phone found on the cable. Plug the other phone in with an OTG cable and turn on its USB debugging. "
                    + "(If it charges but is not found, set its USB mode to \"File transfer\".)");
            return;
        }
        if (!um.hasPermission(dev)) {
            um.requestPermission(dev, PendingIntent.getBroadcast(this, 1, new Intent(USB_ACTION).setPackage(getPackageName()),
                    Build.VERSION.SDK_INT >= 31 ? PendingIntent.FLAG_MUTABLE : 0));
            return;
        }
        UsbDevice d = dev;
        work(s -> {
            UsbDeviceConnection conn = um.openDevice(d);
            if (conn == null) return "Could not open the USB connection.";
            UsbInterface itf = Adb.adbInterface(d);
            try (Adb a = Adb.usb(this, conn, itf, () -> s.accept("Tap \"Allow\" on the other phone (tick \"Always allow\")."))) {
                return Activate.setup(this, a, true, s);
            } catch (Exception e) {
                return Activate.problem(e);
            } finally {
                conn.releaseInterface(itf);
                conn.close();
            }
        }, OTHER_DONE);
    }

    // ================= actions =================

    private boolean passwordOk(EditText pw) {
        if (System.currentTimeMillis() < waitUntil) { toast("Wait a moment before trying again."); return false; }
        if (Guard.check(this, pw.getText().toString())) return true;
        waitUntil = System.currentTimeMillis() + 10_000L * ++wrong;
        toast("Wrong password.");
        return false;
    }

    private boolean battery() {
        return ((PowerManager) getSystemService(POWER_SERVICE)).isIgnoringBatteryOptimizations(getPackageName());
    }

    private void batteryDialog() {
        open(new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:" + getPackageName())));
    }

    // MIUI/HyperOS keeps Autostart as its own app op (10008); 0 = allowed. Unknown: show the button.
    private boolean autostartOn() {
        try {
            android.app.AppOpsManager ops = (android.app.AppOpsManager) getSystemService(APP_OPS_SERVICE);
            java.lang.reflect.Method m = ops.getClass().getMethod("checkOpNoThrow", int.class, int.class, String.class);
            return (int) m.invoke(ops, 10008, getApplicationInfo().uid, getPackageName()) == 0;
        } catch (Throwable e) {
            return false;
        }
    }

    private void autostart() {
        open(new Intent().setComponent(new ComponentName("com.miui.securitycenter", "com.miui.permcenter.autostart.AutoStartManagementActivity")));
    }

    private static boolean xiaomi() {
        return "xiaomi".equalsIgnoreCase(Build.MANUFACTURER);
    }

    // Opens Xiaomi's battery page for Pure Guard only.
    private void xiaomiBattery() {
        open(new Intent().setComponent(new ComponentName("com.miui.powerkeeper", "com.miui.powerkeeper.ui.HiddenAppsConfigActivity"))
                .putExtra("package_name", getPackageName()).putExtra("package_label", getString(R.string.app_name)));
    }

    // Sends this app's own APK; the other phone installs it, then runs setup there.
    private void share() {
        Intent i = new Intent(Intent.ACTION_SEND).setType(ApkProvider.TYPE)
                .putExtra(Intent.EXTRA_STREAM, ApkProvider.URI)
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        i.setClipData(android.content.ClipData.newRawUri("PureGuard.apk", ApkProvider.URI));
        open(Intent.createChooser(i, "Share Pure Guard"));
    }

    private void startVpn() {
        Intent p = VpnService.prepare(this);
        if (p != null) startActivityForResult(p, 1); // only if setup could not pre-approve the VPN
        else startService(new Intent(this, Vpn.class));
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        if (req == 1 && res == RESULT_OK) startService(new Intent(this, Vpn.class));
    }

    private void shizukuSetup() {
        String problem = Sh.problem(this);
        if (problem != null) {
            if (problem.contains("permission")) try { Shizuku.requestPermission(Sh.REQ); } catch (Exception ignored) {}
            say(problem);
            return;
        }
        say("Setting up with Shizuku…");
        new Thread(() -> {
            String out;
            try (InputStream in = getAssets().open("setup.sh")) {
                ByteArrayOutputStream b = new ByteArrayOutputStream();
                byte[] buf = new byte[4096];
                for (int n; (n = in.read(buf)) > 0; ) b.write(buf, 0, n);
                out = Sh.run(b.toString("UTF-8"));
            } catch (Exception e) {
                out = null;
            }
            say(out == null ? "Shizuku stopped. Start it again and retry." : out.trim());
        }).start();
    }

    private boolean watchOn() {
        String s = Settings.Secure.getString(getContentResolver(), Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
        return s != null && s.contains(getPackageName() + "/");
    }

    private void open(Intent i) {
        try { startActivity(i); } catch (Exception e) { toast("This phone has no such screen."); }
    }

    // ================= view helpers (cur = where new views go) =================

    private void section(String title) {
        LinearLayout c = new LinearLayout(this);
        c.setOrientation(LinearLayout.VERTICAL);
        c.setPadding(dp(16), dp(14), dp(16), dp(10));
        c.setBackground(round(CARD, 20));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.bottomMargin = dp(12);
        box.addView(c, lp);
        cur = c;
        TextView h = text(title, 17, TEXT);
        h.setTypeface(Typeface.DEFAULT_BOLD);
    }

    private TextView text(String s, int sp, int color) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(color);
        t.setPadding(0, dp(4), 0, dp(4));
        t.setLineSpacing(0, 1.12f);
        cur.addView(t);
        return t;
    }

    private void para(String s) {
        text(s, 14, SUB);
    }

    private void note(String s) {
        TextView t = text(s, 14, TEXT);
        t.setBackground(round(CARD2, 12));
        t.setPadding(dp(12), dp(10), dp(12), dp(10));
        ((LinearLayout.LayoutParams) t.getLayoutParams()).topMargin = dp(6);
    }

    private void step(int n, String s) {
        LinearLayout r = new LinearLayout(this);
        r.setPadding(0, dp(5), 0, dp(5));
        TextView num = new TextView(this);
        num.setText(String.valueOf(n));
        num.setTextColor(ON_GREEN);
        num.setTextSize(12);
        num.setTypeface(Typeface.DEFAULT_BOLD);
        num.setGravity(Gravity.CENTER);
        num.setBackground(oval(GREEN));
        LinearLayout.LayoutParams np = new LinearLayout.LayoutParams(dp(22), dp(22));
        np.rightMargin = dp(10);
        np.topMargin = dp(1);
        r.addView(num, np);
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextColor(TEXT);
        t.setTextSize(14);
        t.setLineSpacing(0, 1.12f);
        r.addView(t, new LinearLayout.LayoutParams(0, -2, 1));
        cur.addView(r);
    }

    // A status line: dot, label, and a small fix button when it is not done.
    private void check(String label, boolean ok, String fix, Runnable r) {
        LinearLayout row = new LinearLayout(this);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setMinimumHeight(dp(44));
        View dot = new View(this);
        dot.setBackground(oval(ok ? GREEN : AMBER));
        LinearLayout.LayoutParams dl = new LinearLayout.LayoutParams(dp(10), dp(10));
        dl.rightMargin = dp(12);
        row.addView(dot, dl);
        TextView t = new TextView(this);
        t.setText(label);
        t.setTextColor(TEXT);
        t.setTextSize(15);
        row.addView(t, new LinearLayout.LayoutParams(0, -2, 1));
        if (!ok && fix != null) {
            TextView b = new TextView(this);
            b.setText(fix);
            b.setTextColor(ON_GREEN);
            b.setTypeface(Typeface.DEFAULT_BOLD);
            b.setTextSize(13);
            b.setPadding(dp(14), dp(7), dp(14), dp(7));
            b.setBackground(round(AMBER, 14));
            b.setOnClickListener(v -> r.run());
            row.addView(b);
        } else {
            TextView s = new TextView(this);
            s.setText(ok ? "On" : "Off");
            s.setTextColor(ok ? GREEN : AMBER);
            s.setTextSize(13);
            row.addView(s);
        }
        cur.addView(row);
    }

    private EditText field(String hint, boolean password) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setHintTextColor(0xFF5D6F8A);
        e.setTextColor(TEXT);
        e.setTextSize(16);
        e.setSingleLine();
        e.setBackground(round(CARD2, 14));
        e.setPadding(dp(14), dp(12), dp(14), dp(12));
        if (password) e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        e.setTypeface(Typeface.DEFAULT); // password input switches the hint to monospace
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.topMargin = dp(8);
        cur.addView(e, lp);
        return e;
    }

    private void button(String s, int bg, int fg, Runnable r) {
        TextView b = new TextView(this);
        b.setText(s);
        b.setTextColor(fg);
        b.setTextSize(16);
        b.setTypeface(Typeface.DEFAULT_BOLD);
        b.setGravity(Gravity.CENTER);
        b.setMinHeight(dp(52));
        b.setPadding(dp(16), dp(10), dp(16), dp(10));
        android.graphics.drawable.RippleDrawable rd = new android.graphics.drawable.RippleDrawable(
                android.content.res.ColorStateList.valueOf(0x33FFFFFF), round(bg, 16), null);
        b.setBackground(rd);
        b.setClickable(true);
        b.setOnClickListener(v -> r.run());
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.topMargin = dp(10);
        cur.addView(b, lp);
    }

    private void flat(String s, Runnable r) {
        TextView b = text(s, 15, SUB);
        b.setGravity(Gravity.CENTER);
        b.setPadding(0, dp(12), 0, dp(12));
        b.setOnClickListener(v -> r.run());
    }

    private void space(int h) {
        cur.addView(new View(this), new ViewGroup.LayoutParams(1, dp(h)));
    }

    private GradientDrawable round(int color, int radius) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(dp(radius));
        return g;
    }

    private static GradientDrawable oval(int color) {
        GradientDrawable g = new GradientDrawable();
        g.setShape(GradientDrawable.OVAL);
        g.setColor(color);
        return g;
    }

    private void toast(String s) {
        android.widget.Toast.makeText(this, s, android.widget.Toast.LENGTH_SHORT).show();
    }

    private int dp(int v) {
        return (int) (v * getResources().getDisplayMetrics().density);
    }
}
