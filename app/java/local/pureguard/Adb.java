package local.pureguard;

import android.content.Context;
import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;

// A small adb client, so Pure Guard can run setup.sh as the shell user without a PC or Shizuku:
// - Wireless debugging (Android 11+): pair with the 6-digit code, then adb over TLS. Works for
//   this phone (127.0.0.1) and for another phone on the same Wi-Fi.
// - USB cable (OTG): this phone is the host, the other phone needs only USB debugging + "Allow".
// Protocol: AOSP packages/modules/adb (protocol.txt, pairing_connection.cpp). Call off the main thread.
final class Adb implements Closeable {
    static final String PAIRING = "_adb-tls-pairing._tcp", CONNECT = "_adb-tls-connect._tcp";
    private static final int CNXN = 0x4e584e43, AUTH = 0x48545541, OPEN = 0x4e45504f, OKAY = 0x59414b4f,
            WRTE = 0x45545257, CLSE = 0x45534c43, STLS = 0x534c5453;
    private static final int MAX = 16384; // fits one USB bulk transfer on every Android version

    private InputStream in;
    private Link out;
    private int maxData = MAX;

    // Where messages go: a socket stream, or USB bulk transfers (header and payload sent apart).
    private interface Link {
        void send(byte[] header, byte[] data) throws IOException;
    }

    // ---- keys: one RSA key per install, kept in the app's private files ----

    static synchronized KeyPair key(Context c) throws Exception {
        File pub = new File(c.getFilesDir(), "adbkey.pub"), priv = new File(c.getFilesDir(), "adbkey");
        KeyFactory f = KeyFactory.getInstance("RSA");
        if (pub.exists() && priv.exists())
            return new KeyPair(f.generatePublic(new X509EncodedKeySpec(read(pub))), f.generatePrivate(new PKCS8EncodedKeySpec(read(priv))));
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair k = g.generateKeyPair();
        write(priv, k.getPrivate().getEncoded());
        write(pub, k.getPublic().getEncoded());
        return k;
    }

    private static String pubKey(Context c) throws Exception {
        return AdbKeys.pubKey((RSAPublicKey) key(c).getPublic(), "pureguard@" + android.os.Build.MODEL.replace(' ', '_'));
    }

    // ---- pairing (Wireless debugging > Pair device with pairing code) ----

    static void pair(Context c, InetSocketAddress at, String code) throws Exception {
        try (SSLSocket s = tls(c, new Socket(at.getAddress(), at.getPort()), at)) {
            // The TLS session's exported key joins the code, so a man in the middle can't relay it.
            byte[] ekm = android.net.ssl.SSLSockets.exportKeyingMaterial(s, "adb-label\0", null, 64);
            byte[] pw = concat(code.trim().getBytes("UTF-8"), ekm);
            Spake2 sp = new Spake2(true, "adb pair client\0".getBytes("UTF-8"), "adb pair server\0".getBytes("UTF-8"));
            OutputStream o = s.getOutputStream();
            DataInputStream i = new DataInputStream(s.getInputStream());
            packet(o, 0, sp.msg(pw, new SecureRandom()));
            byte[] km = sp.key(packet(i, 0));
            if (km == null) throw new IOException("Pairing failed (bad reply).");
            SecretKeySpec aes = new SecretKeySpec(AdbKeys.hkdf(km, "adb pairing_auth aes-128-gcm key", 16), "AES");
            byte[] info = new byte[8192]; // PeerInfo: type 0 (RSA public key), then the key text
            byte[] k = pubKey(c).getBytes("UTF-8");
            System.arraycopy(k, 0, info, 1, Math.min(k.length, 8190));
            packet(o, 1, gcm(Cipher.ENCRYPT_MODE, aes, info));
            byte[] reply;
            try { reply = packet(i, 1); } catch (EOFException e) { throw new IOException("Wrong pairing code."); }
            gcm(Cipher.DECRYPT_MODE, aes, reply); // fails on a wrong code too
        }
    }

    private static byte[] gcm(int mode, SecretKeySpec k, byte[] b) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(mode, k, new GCMParameterSpec(128, new byte[12])); // nonce = message counter, 0 each way
        return c.doFinal(b);
    }

    private static void packet(OutputStream o, int type, byte[] payload) throws IOException {
        o.write(ByteBuffer.allocate(6).put((byte) 1).put((byte) type).putInt(payload.length).array());
        o.write(payload);
        o.flush();
    }

    private static byte[] packet(DataInputStream i, int type) throws IOException {
        byte[] h = new byte[6];
        i.readFully(h);
        int len = ByteBuffer.wrap(h, 2, 4).getInt();
        if (h[0] != 1 || h[1] != type || len <= 0 || len > 16384) throw new IOException("Pairing failed (bad packet).");
        byte[] b = new byte[len];
        i.readFully(b);
        return b;
    }

    // ---- connecting ----

    // Wireless debugging's connect port (TLS after the STLS handshake).
    static Adb tcp(Context c, InetSocketAddress at) throws Exception {
        Socket raw = new Socket();
        raw.connect(at, 5000);
        raw.setSoTimeout(30000);
        Adb a = new Adb();
        a.useSocket(raw);
        a.handshake(c, () -> {
            SSLSocket s = tls(c, raw, at);
            a.useSocket(s);
        }, null);
        return a;
    }

    // USB cable: the other phone shows "Allow USB debugging?"; onPrompt tells the user to tap Allow.
    static Adb usb(Context c, UsbDeviceConnection conn, UsbInterface itf, Runnable onPrompt) throws Exception {
        UsbEndpoint ein = null, eout = null;
        for (int i = 0; i < itf.getEndpointCount(); i++) {
            UsbEndpoint e = itf.getEndpoint(i);
            if (e.getType() != UsbConstants.USB_ENDPOINT_XFER_BULK) continue;
            if (e.getDirection() == UsbConstants.USB_DIR_IN) ein = e; else eout = e;
        }
        if (ein == null || eout == null || !conn.claimInterface(itf, true)) throw new IOException("Could not open the USB connection.");
        final UsbEndpoint rx = ein, tx = eout;
        Adb a = new Adb();
        a.in = new InputStream() { // bulk reads into a buffer, handed out byte by byte
            final byte[] buf = new byte[MAX];
            int pos, end;

            @Override public int read() throws IOException {
                byte[] one = new byte[1];
                return read(one, 0, 1) < 0 ? -1 : one[0] & 0xff;
            }

            @Override public int read(byte[] b, int off, int len) throws IOException {
                while (pos == end) {
                    int n = conn.bulkTransfer(rx, buf, buf.length, 0);
                    if (n < 0) throw new IOException("USB cable disconnected.");
                    pos = 0;
                    end = n;
                }
                int n = Math.min(len, end - pos);
                System.arraycopy(buf, pos, b, off, n);
                pos += n;
                return n;
            }
        };
        a.out = (h, d) -> {
            if (conn.bulkTransfer(tx, h, h.length, 5000) != h.length) throw new IOException("USB write failed.");
            if (d.length == 0) return;
            if (conn.bulkTransfer(tx, d, d.length, 5000) != d.length) throw new IOException("USB write failed.");
            if (d.length % tx.getMaxPacketSize() == 0) conn.bulkTransfer(tx, new byte[0], 0, 5000); // end-of-transfer marker
        };
        a.handshake(c, null, onPrompt);
        return a;
    }

    static UsbInterface adbInterface(UsbDevice d) {
        for (int i = 0; i < d.getInterfaceCount(); i++) {
            UsbInterface f = d.getInterface(i);
            if (f.getInterfaceClass() == 0xff && f.getInterfaceSubclass() == 0x42 && f.getInterfaceProtocol() == 1) return f;
        }
        return null;
    }

    private interface Upgrade {
        void run() throws Exception;
    }

    private void useSocket(Socket s) throws IOException {
        in = s.getInputStream();
        OutputStream o = s.getOutputStream();
        out = (h, d) -> { o.write(concat(h, d)); o.flush(); };
    }

    private void handshake(Context c, Upgrade toTls, Runnable onPrompt) throws Exception {
        send(CNXN, 0x01000001, 1024 * 1024, "host::\0".getBytes("UTF-8"));
        boolean signed = false;
        while (true) {
            Msg m = read();
            if (m.cmd == CNXN) { maxData = Math.min(MAX, m.arg1); return; }
            if (m.cmd == STLS && toTls != null) {
                send(STLS, 0x01000000, 0, new byte[0]);
                toTls.run();
            } else if (m.cmd == AUTH && m.arg0 == 1) { // token to sign
                if (!signed) {
                    signed = true;
                    send(AUTH, 2, 0, AdbKeys.signToken(key(c), m.data));
                } else { // key not known yet: send it, the phone asks its user
                    send(AUTH, 3, 0, (pubKey(c) + "\0").getBytes("UTF-8"));
                    if (onPrompt != null) onPrompt.run();
                }
            } else throw new IOException("Unexpected reply from the phone.");
        }
    }

    // Runs one command (exec: service, no terminal), feeds it stdin, returns its output.
    String exec(String cmd, byte[] stdin) throws IOException {
        int me = 1, them = 0;
        send(OPEN, me, 0, ("exec:" + cmd + "\0").getBytes("UTF-8"));
        ByteArrayOutputStream outText = new ByteArrayOutputStream();
        int sent = 0;
        boolean canWrite = false;
        while (true) {
            if (canWrite && sent < stdin.length) {
                int n = Math.min(maxData, stdin.length - sent);
                send(WRTE, me, them, java.util.Arrays.copyOfRange(stdin, sent, sent + n));
                sent += n;
                canWrite = false; // wait for OKAY before the next chunk
            }
            Msg m = read();
            if (m.cmd == OKAY) { them = m.arg0; canWrite = true; }
            else if (m.cmd == WRTE) { outText.write(m.data, 0, m.data.length); send(OKAY, me, m.arg0, new byte[0]); }
            else if (m.cmd == CLSE) {
                if (them == 0) throw new IOException("The phone refused: " + cmd);
                send(CLSE, me, them, new byte[0]);
                return outText.toString("UTF-8");
            }
        }
    }

    private static final class Msg {
        int cmd, arg0, arg1;
        byte[] data;
    }

    private void send(int cmd, int a0, int a1, byte[] d) throws IOException {
        int sum = 0;
        for (byte b : d) sum += b & 0xff;
        out.send(ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(cmd).putInt(a0).putInt(a1).putInt(d.length).putInt(sum).putInt(~cmd).array(), d);
    }

    private Msg read() throws IOException {
        byte[] h = new byte[24];
        new DataInputStream(in).readFully(h);
        ByteBuffer b = ByteBuffer.wrap(h).order(ByteOrder.LITTLE_ENDIAN);
        Msg m = new Msg();
        m.cmd = b.getInt();
        m.arg0 = b.getInt();
        m.arg1 = b.getInt();
        int len = b.getInt();
        if (len < 0 || len > 1024 * 1024) throw new IOException("Bad message from the phone.");
        m.data = new byte[len];
        new DataInputStream(in).readFully(m.data);
        return m;
    }

    @Override public void close() {
        try { if (in != null) in.close(); } catch (IOException ignored) {}
    }

    // ---- TLS: our key as the client certificate, any server certificate (pairing checks the code) ----

    private static SSLSocket tls(Context c, Socket raw, InetSocketAddress at) throws Exception {
        KeyPair k = key(c);
        X509Certificate cert = AdbKeys.cert(k);
        // adbd lists its known keys as "CA names"; ignore them and always offer our one key.
        X509ExtendedKeyManager km = new X509ExtendedKeyManager() {
            @Override public String chooseClientAlias(String[] t, Principal[] i, Socket s) { return "k"; }
            @Override public String chooseEngineClientAlias(String[] t, Principal[] i, javax.net.ssl.SSLEngine e) { return "k"; }
            @Override public X509Certificate[] getCertificateChain(String a) { return new X509Certificate[]{cert}; }
            @Override public PrivateKey getPrivateKey(String a) { return k.getPrivate(); }
            @Override public String[] getClientAliases(String t, Principal[] i) { return new String[]{"k"}; }
            @Override public String[] getServerAliases(String t, Principal[] i) { return null; }
            @Override public String chooseServerAlias(String t, Principal[] i, Socket s) { return null; }
        };
        TrustManager tm = new X509TrustManager() {
            @Override public void checkClientTrusted(X509Certificate[] ch, String t) {}
            @Override public void checkServerTrusted(X509Certificate[] ch, String t) {}
            @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        };
        SSLContext ctx = SSLContext.getInstance("TLSv1.3");
        ctx.init(new javax.net.ssl.KeyManager[]{km}, new TrustManager[]{tm}, new SecureRandom());
        SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(raw, at.getHostString(), at.getPort(), true);
        s.setEnabledProtocols(new String[]{"TLSv1.3"});
        s.setUseClientMode(true);
        s.startHandshake();
        return s;
    }

    // ---- finding Wireless debugging's ports (mDNS) ----

    // First service of this type whose address passes `self` (true: this phone's own; false: another
    // phone's). `only` narrows it to one IP when the user typed it. Null after the timeout.
    static InetSocketAddress find(Context c, String type, boolean self, InetAddress only, long ms) throws InterruptedException {
        NsdManager nsd = (NsdManager) c.getSystemService(Context.NSD_SERVICE);
        LinkedBlockingQueue<NsdServiceInfo> found = new LinkedBlockingQueue<>();
        NsdManager.DiscoveryListener l = new NsdManager.DiscoveryListener() {
            @Override public void onServiceFound(NsdServiceInfo s) { found.add(s); }
            @Override public void onServiceLost(NsdServiceInfo s) {}
            @Override public void onDiscoveryStarted(String t) {}
            @Override public void onDiscoveryStopped(String t) {}
            @Override public void onStartDiscoveryFailed(String t, int e) {}
            @Override public void onStopDiscoveryFailed(String t, int e) {}
        };
        Set<InetAddress> mine = localAddresses();
        nsd.discoverServices(type, NsdManager.PROTOCOL_DNS_SD, l);
        try {
            long end = System.currentTimeMillis() + ms;
            for (NsdServiceInfo s; (s = found.poll(Math.max(1, end - System.currentTimeMillis()), TimeUnit.MILLISECONDS)) != null; ) {
                NsdServiceInfo r = resolve(nsd, s);
                if (r == null || r.getHost() == null) continue;
                InetAddress h = r.getHost();
                if (only != null ? !only.equals(h) : mine.contains(h) != self) continue;
                return new InetSocketAddress(self ? InetAddress.getLoopbackAddress() : h, r.getPort());
            }
            return null;
        } finally {
            try { nsd.stopServiceDiscovery(l); } catch (Exception ignored) {}
        }
    }

    @SuppressWarnings("deprecation")
    private static NsdServiceInfo resolve(NsdManager nsd, NsdServiceInfo s) throws InterruptedException {
        NsdServiceInfo[] out = new NsdServiceInfo[1];
        CountDownLatch done = new CountDownLatch(1);
        nsd.resolveService(s, new NsdManager.ResolveListener() {
            @Override public void onResolveFailed(NsdServiceInfo i, int e) { done.countDown(); }
            @Override public void onServiceResolved(NsdServiceInfo i) { out[0] = i; done.countDown(); }
        });
        done.await(5, TimeUnit.SECONDS);
        return out[0];
    }

    private static Set<InetAddress> localAddresses() {
        Set<InetAddress> s = new HashSet<>();
        try {
            for (NetworkInterface n : Collections.list(NetworkInterface.getNetworkInterfaces()))
                s.addAll(Collections.list(n.getInetAddresses()));
        } catch (Exception ignored) {}
        return s;
    }

    // ---- small helpers ----

    static byte[] concat(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    static byte[] read(File f) throws IOException {
        try (InputStream i = new FileInputStream(f)) { return readAll(i); }
    }

    static byte[] readAll(InputStream i) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        byte[] buf = new byte[65536];
        for (int n; (n = i.read(buf)) > 0; ) b.write(buf, 0, n);
        return b.toByteArray();
    }

    private static void write(File f, byte[] b) throws IOException {
        try (java.io.FileOutputStream o = new java.io.FileOutputStream(f)) { o.write(b); }
    }
}
