package local.pureguard;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

// DNS-only VPN. Only the fake DNS server and the public DNS / DNS-over-HTTPS addresses are routed
// into the tunnel, so normal traffic never passes through this app. Every DNS question is checked
// against the blocklist; allowed ones go to CleanBrowsing's adult filter. Packets to the DoH
// addresses are dropped, so browsers fall back to normal DNS.
public final class Vpn extends VpnService implements Runnable {
    static volatile boolean running;
    static final String DNS = "10.111.222.53";
    static final String[] UPSTREAM = {"185.228.168.10", "185.228.169.11"}; // CleanBrowsing adult filter
    // Same lists as the tablet lock (netcfg core.sh DOH4/DOH6): public resolvers apps may hardcode.
    static final String[] DOH4 = ("1.1.1.1 1.0.0.1 1.1.1.2 1.0.0.2 1.1.1.3 1.0.0.3 8.8.8.8 8.8.4.4 9.9.9.9 "
            + "149.112.112.112 9.9.9.10 149.112.112.10 9.9.9.11 149.112.112.11 208.67.222.222 208.67.220.220 "
            + "208.67.222.123 208.67.220.123 94.140.14.14 94.140.15.15 94.140.14.140 94.140.14.141 45.90.28.0/24 "
            + "45.90.30.0/24 76.76.2.0/24 76.76.10.0/24 194.242.2.0/24 185.222.222.222 45.11.45.11 86.54.11.0/24 "
            + "76.223.122.150 76.76.19.19 162.159.36.1 162.159.46.1 162.159.132.53 162.159.61.4 172.64.41.4").split(" ");
    static final String[] DOH6 = ("2606:4700:4700::/48 2001:4860:4860::8888 2001:4860:4860::8844 2620:fe::/48 "
            + "2620:119:35::35 2620:119:53::53 2a10:50c0::/32 2a07:a8c0::/32 2a07:e340::/32 2a00:5a60::/32").split(" ");

    private Thread loop;
    private ParcelFileDescriptor tun;
    private FileOutputStream out;
    private final ExecutorService pool = Executors.newFixedThreadPool(8);
    private final ScheduledExecutorService tick = Executors.newSingleThreadScheduledExecutor();

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Always-on VPN starts this service by itself, also after "Unlock and remove": no filter then.
        if (!Guard.locked(this)) {
            Guard.releaseAlwaysOn(this);
            close(); // Android stays bound to an established VPN: stopService alone never ends it
            stopSelf();
            return START_NOT_STICKY;
        }
        if (loop == null) {
            loop = new Thread(this, "pureguard-vpn");
            loop.start();
            tick.scheduleWithFixedDelay(() -> {
                if (Guard.locked(this)) Guard.heal(this);
                else { close(); stopSelf(); }
            }, 60, 60, TimeUnit.SECONDS);
        }
        return START_STICKY;
    }

    @Override
    public void run() {
        try {
            Dns.load(getAssets().open("block.txt"), getAssets().open("wild.txt"));
            Builder b = new Builder().setSession(getString(R.string.app_name)).setMtu(1500).setBlocking(true)
                    .addAddress("10.111.222.1", 32).addDnsServer(DNS).addRoute(DNS, 32);
            route(b, DOH4);
            try {
                b.addAddress("fd00:7067::1", 128);
                route(b, DOH6);
            } catch (Exception ignored) { /* no IPv6 in this VPN: v4 rules still hold */ }
            b.addDisallowedApplication(getPackageName()); // our own lookups (SafeSearch targets) skip the tunnel
            tun = b.establish();
            if (tun == null) { stopSelf(); return; }
            out = new FileOutputStream(tun.getFileDescriptor());
            running = true;
            Guard.vpnUp(this);
            FileInputStream in = new FileInputStream(tun.getFileDescriptor());
            byte[] buf = new byte[32767];
            for (int n; (n = in.read(buf)) > 0; ) {
                byte[] p = Arrays.copyOf(buf, n);
                byte[] q = Dns.query(p, n);
                if (q != null) pool.execute(() -> answer(p, q));
                // anything else (a DoH connection) is dropped here
            }
        } catch (Exception ignored) {
        } finally {
            running = false;
        }
    }

    private static void route(Builder b, String[] list) {
        for (String r : list) {
            int i = r.indexOf('/');
            String ip = i < 0 ? r : r.substring(0, i);
            int bits = i < 0 ? (ip.contains(":") ? 128 : 32) : Integer.parseInt(r.substring(i + 1));
            b.addRoute(ip, bits);
        }
    }

    private void answer(byte[] p, byte[] q) {
        String name = Dns.qname(q);
        if (name == null) return;
        byte[] r;
        try {
            String safe;
            if (Dns.blocked(name)) r = Dns.reply(q, 3, null); // NXDOMAIN: "site can't be reached"
            else if ((safe = Dns.safeTarget(name)) != null)
                r = Dns.reply(q, 0, Dns.qtype(q) == 1 ? Dns.v4(InetAddress.getAllByName(safe)) : null);
            else r = forward(q);
        } catch (Exception e) {
            r = Dns.reply(q, 2, null); // SERVFAIL: the app retries
        }
        if (r == null) return;
        byte[] pkt = Dns.wrap(p, r);
        synchronized (this) {
            try { out.write(pkt); } catch (Exception ignored) {}
        }
    }

    private byte[] forward(byte[] q) throws Exception {
        try (DatagramSocket s = new DatagramSocket()) {
            protect(s);
            s.setSoTimeout(2500);
            byte[] buf = new byte[4096];
            for (String up : UPSTREAM) {
                try {
                    s.send(new DatagramPacket(q, q.length, InetAddress.getByName(up), 53));
                    DatagramPacket in = new DatagramPacket(buf, buf.length);
                    s.receive(in);
                    return Arrays.copyOf(buf, in.getLength());
                } catch (java.net.SocketTimeoutException ignored) { /* try the second server */ }
            }
        }
        return null;
    }

    private synchronized void close() {
        try { if (tun != null) tun.close(); } catch (Exception ignored) {}
        tun = null;
    }

    @Override
    public void onRevoke() {
        stopSelf();
    }

    @Override
    public void onDestroy() {
        running = false;
        tick.shutdownNow();
        pool.shutdownNow();
        close();
        Guard.vpnDown(this);
        super.onDestroy();
    }
}
