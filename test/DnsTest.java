package local.pureguard;

import java.io.FileInputStream;
import java.net.InetAddress;
import java.util.Collections;

// PC self-test for Dns.java (filter, DNS messages, IPv4/IPv6 packets). Run: test/run.sh
public final class DnsTest {
    static int fails;

    static void ok(boolean c, String what) {
        if (!c) { fails++; System.out.println("FAIL " + what); }
    }

    public static void main(String[] a) throws Exception {
        Dns.load(new FileInputStream(a[0]), new FileInputStream(a[1]));
        ok(Dns.BLOCK.size() > 100000, "blocklist loaded: " + Dns.BLOCK.size());

        // filter
        ok(Dns.blocked("pornhub.com"), "pornhub");
        ok(Dns.blocked("www.xvideos.com."), "xvideos with trailing dot");
        ok(Dns.blocked("anihq.cc") && Dns.blocked("cdn.anihq.cc"), "wild anihq");
        ok(Dns.blocked("a.b.hitomi.la"), "wild hitomi deep");
        ok(Dns.blocked("dns.google") && Dns.blocked("mozilla.cloudflare-dns.com"), "DoH names");
        ok(Dns.blocked("some-new-hentai-site.net"), "keyword");
        for (String s : new String[]{"google.com", "www.youtube.com", "essex.ac.uk", "facebook.com",
                "jw.org", "wol.jw.org", "weebcentral.com", "messenger.com", "github.com", "sussex.ac.uk"})
            ok(!Dns.blocked(s), "not blocked: " + s);

        // address bar
        ok(Dns.badUrl("https://anihq.cc/watch/1"), "url anihq");
        ok(Dns.badUrl("anihq.cc. Connection is not secure"), "Chrome's url_bar text");
        ok(!Dns.badUrl("jw.org. Connection is secure"), "Chrome's url_bar text, allowed site");
        ok(Dns.badUrl("nude pictures"), "search words");
        ok(Dns.badUrl("pornhub"), "typed keyword");
        ok(!Dns.badUrl("https://www.jw.org/en/library/"), "jw.org url");
        ok(!Dns.badUrl("how to fix safe mode"), "normal search");

        // SafeSearch
        ok("forcesafesearch.google.com".equals(Dns.safeTarget("www.google.com.ph")), "google.com.ph");
        ok("forcesafesearch.google.com".equals(Dns.safeTarget("google.com")), "google.com");
        ok(Dns.safeTarget("mail.google.com") == null, "gmail untouched");
        ok("strict.bing.com".equals(Dns.safeTarget("www.bing.com")), "bing");
        ok("restrictmoderate.youtube.com".equals(Dns.safeTarget("m.youtube.com")), "youtube");

        // DNS message: query for pornhub.com, type A, with an EDNS OPT record after the question
        byte[] q = msg("pornhub.com", 1, true);
        ok("pornhub.com".equals(Dns.qname(q)), "qname");
        ok(Dns.qtype(q) == 1, "qtype");
        byte[] nx = Dns.reply(q, 3, null);
        ok((nx[2] & 0x80) != 0 && (nx[3] & 0x0f) == 3 && nx[0] == q[0] && nx[1] == q[1], "NXDOMAIN header and id");
        ok(nx[11] == 0 && nx.length == 12 + 13 + 4, "OPT record dropped, question kept");
        byte[] ans = Dns.reply(q, 0, Collections.singletonList(InetAddress.getByName("216.239.38.120")));
        ok(ans[7] == 1 && (ans[ans.length - 4] & 0xff) == 216 && (ans[ans.length - 1] & 0xff) == 120, "A record");
        ok(Dns.qname(ans) == null, "a reply is not taken as a query");

        // IPv4 packet in, reply out
        byte[] p4 = ip4(q);
        ok(Dns.query(p4, p4.length) != null, "v4 query found");
        byte[] r4 = Dns.wrap(p4, nx);
        ok(fold(sum(r4, 0, 20, 0)) == 0, "v4 header checksum");
        ok(eq(r4, 12, p4, 16, 4) && eq(r4, 16, p4, 12, 4), "v4 addresses swapped");
        ok((r4[20] & 0xff) << 8 == 0 && r4[21] == 53 && r4[22] == p4[20] && r4[23] == p4[21], "v4 ports swapped");
        ok(((r4[2] & 0xff) << 8 | (r4[3] & 0xff)) == r4.length, "v4 total length");

        // IPv6 packet in, reply out: UDP checksum must verify
        byte[] p6 = ip6(q);
        ok(Dns.query(p6, p6.length) != null, "v6 query found");
        byte[] r6 = Dns.wrap(p6, nx);
        int ulen = r6.length - 40;
        ok(fold(sum(r6, 40, ulen, sum(r6, 8, 32, 0) + ulen + 17)) == 0, "v6 UDP checksum");
        ok(eq(r6, 8, p6, 24, 16) && eq(r6, 24, p6, 8, 16), "v6 addresses swapped");

        // not DNS: TCP, or UDP to another port
        byte[] tcp = p4.clone(); tcp[9] = 6;
        ok(Dns.query(tcp, tcp.length) == null, "tcp ignored");
        byte[] other = p4.clone(); other[23] = 54;
        ok(Dns.query(other, other.length) == null, "udp 54 ignored");

        System.out.println(fails == 0 ? "ALL OK" : fails + " FAILED");
        System.exit(fails == 0 ? 0 : 1);
    }

    static byte[] msg(String name, int type, boolean opt) {
        java.io.ByteArrayOutputStream b = new java.io.ByteArrayOutputStream();
        b.write(0x12); b.write(0x34); b.write(0x01); b.write(0x00); // id, RD
        b.write(0); b.write(1); b.write(0); b.write(0); b.write(0); b.write(0); b.write(0); b.write(opt ? 1 : 0);
        for (String l : name.split("\\.")) { b.write(l.length()); b.write(l.getBytes(), 0, l.length()); }
        b.write(0); b.write(0); b.write(type); b.write(0); b.write(1);
        if (opt) { byte[] o = {0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0}; b.write(o, 0, o.length); }
        return b.toByteArray();
    }

    static byte[] ip4(byte[] dns) {
        byte[] p = new byte[28 + dns.length];
        p[0] = 0x45; p[9] = 17; p[2] = (byte) (p.length >> 8); p[3] = (byte) p.length;
        byte[] src = {10, 111, (byte) 222, 1}, dst = {10, 111, (byte) 222, 53};
        System.arraycopy(src, 0, p, 12, 4); System.arraycopy(dst, 0, p, 16, 4);
        p[20] = (byte) 0xc3; p[21] = 0x50; p[23] = 53;
        p[24] = (byte) ((8 + dns.length) >> 8); p[25] = (byte) (8 + dns.length);
        System.arraycopy(dns, 0, p, 28, dns.length);
        return p;
    }

    static byte[] ip6(byte[] dns) {
        byte[] p = new byte[48 + dns.length];
        p[0] = 0x60; p[6] = 17; p[7] = 64;
        p[4] = (byte) ((8 + dns.length) >> 8); p[5] = (byte) (8 + dns.length);
        p[8] = (byte) 0xfd; p[23] = 1;                                       // fd00::1
        p[24] = 0x20; p[25] = 0x01; p[26] = 0x48; p[27] = 0x60; p[39] = (byte) 0x88; // 2001:4860::88
        p[40] = 0x7a; p[41] = 0x11; p[43] = 53;
        p[44] = p[4]; p[45] = p[5];
        System.arraycopy(dns, 0, p, 48, dns.length);
        return p;
    }

    static boolean eq(byte[] a, int ao, byte[] b, int bo, int n) {
        for (int i = 0; i < n; i++) if (a[ao + i] != b[bo + i]) return false;
        return true;
    }

    static long sum(byte[] b, int off, int len, long s) {
        for (int i = 0; i < len; i += 2) s += (b[off + i] & 0xff) << 8 | (i + 1 < len ? b[off + i + 1] & 0xff : 0);
        return s;
    }

    static int fold(long s) {
        while ((s >> 16) != 0) s = (s & 0xffff) + (s >> 16);
        return (int) (~s & 0xffff);
    }
}
