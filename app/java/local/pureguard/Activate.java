package local.pureguard;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.RemoteInput;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import java.io.File;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.function.Consumer;

// Runs setup.sh through Adb: on this phone (Wireless debugging, code typed into a notification,
// because leaving Settings closes the pairing popup) or on another phone (Wi-Fi or USB cable),
// installing Pure Guard there first. This class is also the receiver of the notification's reply.
public final class Activate extends BroadcastReceiver {
    private static final int ID = 7;

    // ---- this phone ----

    // Shows (or updates) the notification; withInput adds the "Enter code" reply box.
    static void notify(Context c, String text, boolean withInput) {
        Guard.prefs(c).edit().putString("act", text).apply();
        NotificationManager nm = c.getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel("act", "Activation", NotificationManager.IMPORTANCE_HIGH));
        Notification.Builder b = new Notification.Builder(c, "act")
                .setSmallIcon(R.drawable.ic_fg)
                .setContentTitle("Pure Guard activation")
                .setContentText(text)
                .setStyle(new Notification.BigTextStyle().bigText(text))
                .setOnlyAlertOnce(true);
        if (withInput) {
            PendingIntent pi = PendingIntent.getBroadcast(c, 0, new Intent(c, Activate.class),
                    PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= 31 ? PendingIntent.FLAG_MUTABLE : 0));
            b.addAction(new Notification.Action.Builder(android.graphics.drawable.Icon.createWithResource(c, R.drawable.ic_fg),
                    "Enter pairing code", pi)
                    .addRemoteInput(new RemoteInput.Builder("code").setLabel("6-digit code").build()).build());
        }
        nm.notify(ID, b.build());
    }

    static void cancel(Context c) {
        c.getSystemService(NotificationManager.class).cancel(ID);
    }

    @Override
    public void onReceive(Context c, Intent i) {
        Bundle r = RemoteInput.getResultsFromIntent(i);
        CharSequence code = r == null ? null : r.getCharSequence("code");
        if (code == null || code.toString().trim().isEmpty()) return;
        PendingResult pr = goAsync();
        Context app = c.getApplicationContext();
        new Thread(() -> {
            try {
                String err = self(app, code.toString(), s -> notify(app, s, false));
                if (err == null) notify(app, "Activated ✓  Open Pure Guard to finish.", false);
                else notify(app, err + "\nOpen the pairing popup again, then enter the new code.", true);
            } finally {
                pr.finish();
            }
        }).start();
    }

    static final String NEED_CODE = "need-code";

    // Wireless debugging on and this install paired before: reconnect with the saved key, no code.
    // Null when done, NEED_CODE when never paired or the phone forgot the key, else the problem.
    static String selfAuto(Context c, Consumer<String> step) {
        if (!Update.prefs(c).getBoolean("self_paired", false)) return NEED_CODE;
        InetSocketAddress at;
        try {
            step.accept("Wireless debugging is on. Connecting…");
            at = Adb.find(c, Adb.CONNECT, true, null, 5000);
        } catch (InterruptedException e) {
            return problem(e);
        }
        if (at == null) return "Wireless debugging is not ready yet. Try again in a moment.";
        Adb a;
        try {
            a = Adb.tcp(c, at);
        } catch (Exception e) {
            Update.prefs(c).edit().putBoolean("self_paired", false).apply();
            return NEED_CODE; // adbd refused our key: the pairing was removed or expired
        }
        try {
            step.accept("Setting up…");
            return setup(c, a, false, step);
        } catch (Exception e) {
            return problem(e);
        } finally {
            a.close();
        }
    }

    // Null when done, else what went wrong (in words for the phone's user).
    static String self(Context c, String code, Consumer<String> step) {
        try {
            step.accept("Looking for the pairing popup…");
            InetSocketAddress p = Adb.find(c, Adb.PAIRING, true, null, 8000);
            if (p == null) return "Pairing popup not found. Keep \"Pair device with pairing code\" open while you type the code.";
            step.accept("Pairing…");
            Adb.pair(c, p, code);
            Update.prefs(c).edit().putBoolean("self_paired", true).apply(); // later: no code needed
            step.accept("Paired. Connecting…");
            InetSocketAddress at = Adb.find(c, Adb.CONNECT, true, null, 10000);
            if (at == null) return "Paired, but Wireless debugging is off now. Turn it on and try again.";
            try (Adb a = Adb.tcp(c, at)) {
                step.accept("Setting up…");
                return setup(c, a, false, step);
            }
        } catch (Exception e) {
            return problem(e);
        }
    }

    // ---- another phone ----

    // Same Wi-Fi: finds the other phone's pairing popup by itself; `typed` ("ip:port") if not found.
    static String wifi(Context c, String code, String typed, Consumer<String> step) {
        try {
            InetSocketAddress p;
            if (code.isEmpty()) { // paired with this phone before: connect straight away
                step.accept("Looking for the other phone on this Wi-Fi…");
                InetAddress only = typed == null || typed.trim().isEmpty() ? null : InetAddress.getByName(typed.trim().split(":")[0]);
                InetSocketAddress at = Adb.find(c, Adb.CONNECT, false, only, 10000);
                if (at == null) return "Other phone not found. Is Wireless debugging on, on the same Wi-Fi?";
                Adb a;
                try {
                    a = Adb.tcp(c, at);
                } catch (Exception e) {
                    return "That phone is not paired with this one yet. Type the pairing code from its popup.";
                }
                try (Adb ignored = a) {
                    return setup(c, a, true, step);
                }
            }
            if (typed != null && !typed.trim().isEmpty()) {
                String[] hp = typed.trim().split(":");
                if (hp.length != 2) return "Type the address like 192.168.1.20:37155";
                p = new InetSocketAddress(InetAddress.getByName(hp[0]), Integer.parseInt(hp[1]));
            } else {
                step.accept("Looking for the other phone on this Wi-Fi…");
                p = Adb.find(c, Adb.PAIRING, false, null, 10000);
                if (p == null) return "Other phone not found. Is it on the same Wi-Fi with the pairing popup open? "
                        + "Or type the IP address & port shown in its popup.";
            }
            step.accept("Pairing with " + p.getAddress().getHostAddress() + "…");
            Adb.pair(c, p, code);
            step.accept("Paired. Connecting…");
            InetSocketAddress at = Adb.find(c, Adb.CONNECT, false, p.getAddress(), 10000);
            if (at == null) return "Paired, but could not connect. Keep Wireless debugging on, then try again.";
            try (Adb a = Adb.tcp(c, at)) {
                return setup(c, a, true, step);
            }
        } catch (Exception e) {
            return problem(e);
        }
    }

    // Installs this very APK on the other phone (when asked), then runs setup.sh as its shell user.
    static String setup(Context c, Adb a, boolean install, Consumer<String> step) throws Exception {
        if (install) {
            step.accept("Installing Pure Guard on the other phone…");
            byte[] apk = Adb.read(new File(c.getApplicationInfo().sourceDir));
            String r = a.exec("cmd package install -r -S " + apk.length, apk);
            if (!r.contains("Success"))
                return "Install failed: " + r.trim() + "\nXiaomi: turn on \"Install via USB\" in Developer options.";
        }
        step.accept("Running setup…");
        String script;
        try (InputStream in = c.getAssets().open("setup.sh")) { script = new String(Adb.readAll(in), "UTF-8"); }
        String out = a.exec("sh", ("exec 2>&1\n" + script + "\nexit\n").getBytes("UTF-8"));
        if (out.contains("SETUP-OK") && !out.contains("Exception")) return null;
        return "Setup did not finish:\n" + out.trim()
                + (out.contains("SecurityException") ? "\nXiaomi: turn on \"USB debugging (Security settings)\"." : "");
    }

    static String problem(Exception e) {
        String m = e.getMessage();
        if (e instanceof java.net.ConnectException) return "Could not reach the phone. Is Wireless debugging still on?";
        if (e instanceof javax.crypto.AEADBadTagException) return "Wrong pairing code.";
        return m == null || m.isEmpty() ? e.getClass().getSimpleName() : m;
    }
}
