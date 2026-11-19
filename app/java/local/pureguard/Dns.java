package local.pureguard;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

// The filter and the packet code, with no Android classes so test/DnsTest.java runs it on a PC.
final class Dns {
    // block.txt: exact names (the tablet's hosts list). wild.txt: a name and all its subdomains.
    static final Set<String> BLOCK = new HashSet<>(160000);
    static final Set<String> WILD = new HashSet<>();
    // Any name containing one of these is porn-only in practice.
    static final String[] WORDS = {"porn", "hentai", "xxx", "xvideo", "xhamster", "rule34", "redtube",
            "youporn", "brazzers", "onlyfans", "chaturbate", "stripchat", "nsfw", "hanime", "nhentai"};
    // Address-bar text (URLs and searches) also stops on these.
    static final String[] URL_WORDS = {"nude", "naked", "r18", "rule 34", "18+", "sex video", "sexvideo"};

    static final Pattern GOOGLE = Pattern.compile("(www\\.)?google\\.(com|[a-z]{2}|com?\\.[a-z]{2})");
    static final Set<String> YOUTUBE = new HashSet<>(java.util.Arrays.asList("www.youtube.com", "m.youtube.com",
            "youtubei.googleapis.com", "youtube.googleapis.com", "www.youtube-nocookie.com"));

    private Dns() {}

    static synchronized void load(InputStream block, InputStream wild) throws IOException {
        if (!BLOCK.isEmpty()) return;
        read(block, BLOCK);
        read(wild, WILD);
    }

    private static void read(InputStream in, Set<String> into) throws IOException {
        try (BufferedReader r = new BufferedReader(new InputStreamReader(in, "UTF-8"))) {
            for (String l; (l = r.readLine()) != null; ) {
                l = l.trim();
                if (!l.isEmpty() && l.charAt(0) != '#') into.add(l.toLowerCase());
            }
        }
    }

    static boolean blocked(String host) {
        if (host == null || host.isEmpty()) return false;
        host = host.toLowerCase();
        if (host.endsWith(".")) host = host.substring(0, host.length() - 1);
        if (BLOCK.contains(host)) return true;
        for (String h = host; ; ) {
            if (WILD.contains(h)) return true;
            int i = h.indexOf('.');
            if (i < 0) break;
            h = h.substring(i + 1);
        }
        for (String w : WORDS) if (host.contains(w)) return true;
        return false;
    }

    // Address-bar text: a URL or a search being typed.
    static boolean badUrl(String text) {
        if (text == null) return false;
        String t = text.toLowerCase().trim();
        for (String w : WORDS) if (t.contains(w)) return true;
        for (String w : URL_WORDS) if (t.contains(w)) return true;
        // Chrome adds words after the host ("anihq.cc. Connection is not secure"): the host is the first token.
        String host = t.replaceFirst("^[a-z]+://", "").split("[\\s/?#]", 2)[0];
        return host.indexOf('.') > 0 && blocked(host);
    }

    // SafeSearch: these names are answered with the addresses of the strict version.
    static String safeTarget(String host) {
        host = host.toLowerCase();
        if (GOOGLE.matcher(host).matches()) return "forcesafesearch.google.com";
        if (host.equals("www.bing.com") || host.equals("bing.com")) return "strict.bing.com";
        if (YOUTUBE.contains(host)) return "restrictmoderate.youtube.com";
        return null;
    }

    // ---- DNS messages ----

    // The question name, or null when the message is not a plain one-question query.
    static String qname(byte[] m) {
        if (m.length < 17 || (m[2] & 0x80) != 0 || ((m[4] & 0xff) << 8 | (m[5] & 0xff)) != 1) return null;
        StringBuilder b = new StringBuilder();
        int i = 12;
        while (i < m.length) {
            int n = m[i] & 0xff;
            if (n == 0) return b.length() == 0 ? null : b.toString().toLowerCase();
            if (n > 63 || i + 1 + n > m.length) return null;
            if (b.length() > 0) b.append('.');
            for (int k = 1; k <= n; k++) b.append((char) (m[i + k] & 0xff));
            i += 1 + n;
        }
        return null;
    }

    static int qtype(byte[] m) {
        int i = 12;
        while (i < m.length && m[i] != 0) i += 1 + (m[i] & 0xff);
        return i + 2 < m.length ? (m[i + 1] & 0xff) << 8 | (m[i + 2] & 0xff) : -1;
    }

    // A reply to query q: header + question copied, then one A record per address.
    static byte[] reply(byte[] q, int rcode, List<InetAddress> v4) {
        int qEnd = 12;
        while (q[qEnd] != 0) qEnd += 1 + (q[qEnd] & 0xff);
        qEnd += 5; // zero byte, type, class
        int an = v4 == null ? 0 : v4.size();
        byte[] r = new byte[qEnd + an * 16];
        System.arraycopy(q, 0, r, 0, qEnd);
        r[2] = (byte) (0x80 | (q[2] & 0x79)); // QR, keep opcode and RD
        r[3] = (byte) (0x80 | rcode);         // RA
        r[6] = (byte) (an >> 8); r[7] = (byte) an;
        r[8] = r[9] = r[10] = r[11] = 0;
        int o = qEnd;
        for (int k = 0; k < an; k++) {
            byte[] a = v4.get(k).getAddress();
            byte[] rec = {(byte) 0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, a[0], a[1], a[2], a[3]};
            System.arraycopy(rec, 0, r, o, 16);
            o += 16;
        }
        return r;
    }

    static List<InetAddress> v4(InetAddress[] all) {
        List<InetAddress> l = new ArrayList<>();
        for (InetAddress a : all) if (a instanceof Inet4Address) l.add(a);
        return l;
    }

    // ---- IP packets from the tun device ----

    // The DNS payload of a UDP packet to port 53 (IPv4 or IPv6), or null.
    static byte[] query(byte[] p, int len) {
        int h = header(p, len);
        if (h < 0 || len < h + 8 + 12) return null;
        if (((p[h + 2] & 0xff) << 8 | (p[h + 3] & 0xff)) != 53) return null;
        byte[] d = new byte[len - h - 8];
        System.arraycopy(p, h + 8, d, 0, d.length);
        return d;
    }

    // UDP header offset, or -1 when the packet is not UDP.
    private static int header(byte[] p, int len) {
        if (len < 28) return -1;
        int v = (p[0] & 0xff) >> 4;
        if (v == 4) return p[9] == 17 ? (p[0] & 0x0f) * 4 : -1;
        if (v == 6) return len >= 48 && p[6] == 17 ? 40 : -1;
        return -1;
    }

    // The reply packet: addresses and ports of request p swapped, payload dns.
    static byte[] wrap(byte[] p, byte[] dns) {
        boolean v6 = (p[0] & 0xff) >> 4 == 6;
        int ih = v6 ? 40 : 20, src = v6 ? 8 : 12, dst = v6 ? 24 : 16, al = v6 ? 16 : 4;
        int h = v6 ? 40 : (p[0] & 0x0f) * 4;
        int ulen = 8 + dns.length;
        byte[] r = new byte[ih + ulen];
        if (v6) {
            r[0] = 0x60;
            r[4] = (byte) (ulen >> 8); r[5] = (byte) ulen;
            r[6] = 17; r[7] = 64;
        } else {
            r[0] = 0x45;
            r[2] = (byte) (r.length >> 8); r[3] = (byte) r.length;
            r[6] = 0x40; r[8] = 64; r[9] = 17;
        }
        System.arraycopy(p, dst, r, src, al);
        System.arraycopy(p, src, r, dst, al);
        r[ih] = p[h + 2]; r[ih + 1] = p[h + 3];     // from port 53
        r[ih + 2] = p[h]; r[ih + 3] = p[h + 1];     // to the asking port
        r[ih + 4] = (byte) (ulen >> 8); r[ih + 5] = (byte) ulen;
        System.arraycopy(dns, 0, r, ih + 8, dns.length);
        if (v6) {
            // UDP checksum is mandatory on IPv6: pseudo header (addresses, length, protocol) + UDP.
            long s = sum(r, 8, 32, 0) + ulen + 17;
            int c = fold(sum(r, ih, ulen, s));
            if (c == 0) c = 0xffff;
            r[ih + 6] = (byte) (c >> 8); r[ih + 7] = (byte) c;
        } else {
            int c = fold(sum(r, 0, 20, 0));
            r[10] = (byte) (c >> 8); r[11] = (byte) c;
        }
        return r;
    }

    private static long sum(byte[] b, int off, int len, long s) {
        for (int i = 0; i < len; i += 2) s += (b[off + i] & 0xff) << 8 | (i + 1 < len ? b[off + i + 1] & 0xff : 0);
        return s;
    }

    private static int fold(long s) {
        while ((s >> 16) != 0) s = (s & 0xffff) + (s >> 16);
        return (int) (~s & 0xffff);
    }
}
