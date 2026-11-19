package local.pureguard;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

// SPAKE2 over Ed25519, byte-compatible with BoringSSL's spake25519.cc, which adbd uses for
// "Pair device with pairing code". Plain BigInteger math: slow next to BoringSSL, but it runs
// once per pairing (a few ms). Pure Java so test/Spake2Test.java checks it on the PC.
final class Spake2 {
    static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    static final BigInteger L = BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
    static final BigInteger D = BigInteger.valueOf(-121665).multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P);
    private static final BigInteger SQRT_M1 = BigInteger.valueOf(2).modPow(P.subtract(BigInteger.ONE).shiftRight(2), P);
    static final BigInteger[] B = decode(hex("5866666666666666666666666666666666666666666666666666666666666666"));
    // Fixed points from spake25519.cc (generated there from SHA-256 seeds; the test re-derives them).
    static final BigInteger[] M = decode(hex("5ada7e4bf6ddd9adb6626d32131c6b5c51a1e347a3478f53cfcf441b88eed12e"));
    static final BigInteger[] N = decode(hex("10e3df0ae37d8e7a99b5fe74b44672103dbddcbd06af680d71329a11693bc778"));

    private final boolean alice;
    private final byte[] myName, theirName;
    private BigInteger priv, pwScalar;
    private byte[] pwHash, myMsg;

    Spake2(boolean alice, byte[] myName, byte[] theirName) {
        this.alice = alice;
        this.myName = myName;
        this.theirName = theirName;
    }

    // SPAKE2_generate_msg: P* = 8r·B + s·(M or N), s = password scalar.
    byte[] msg(byte[] password, SecureRandom rnd) {
        byte[] r = new byte[64];
        rnd.nextBytes(r);
        priv = le(r).mod(L).shiftLeft(3); // multiple of 8 clears the peer point's cofactor
        pwHash = sha512(password);
        BigInteger s = le(pwHash).mod(L);
        // BoringSSL's "password scalar hack": add l, 2l, 4l so the low 3 bits become 0.
        if (s.testBit(0)) s = s.add(L);
        if (s.testBit(1)) s = s.add(L.shiftLeft(1));
        if (s.testBit(2)) s = s.add(L.shiftLeft(2));
        pwScalar = s;
        myMsg = encode(add(mul(priv, B), mul(s, alice ? M : N)));
        return myMsg.clone();
    }

    // SPAKE2_process_msg: the 64-byte shared key, or null for a point not on the curve.
    byte[] key(byte[] theirMsg) {
        BigInteger[] q = theirMsg.length == 32 ? decode(theirMsg) : null;
        if (q == null) return null;
        byte[] dh = encode(mul(priv, add(q, neg(mul(pwScalar, alice ? N : M)))));
        try {
            MessageDigest h = MessageDigest.getInstance("SHA-512");
            if (alice) { put(h, myName); put(h, theirName); put(h, myMsg); put(h, theirMsg); }
            else { put(h, theirName); put(h, myName); put(h, theirMsg); put(h, myMsg); }
            put(h, dh);
            put(h, pwHash);
            return h.digest();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void put(MessageDigest h, byte[] b) {
        long n = b.length;
        for (int i = 0; i < 8; i++, n >>>= 8) h.update((byte) n); // 8-byte little-endian length
        h.update(b);
    }

    // ---- Ed25519 group, extended coordinates {X, Y, Z, T} ----

    static BigInteger[] add(BigInteger[] p, BigInteger[] q) {
        BigInteger a = p[1].subtract(p[0]).multiply(q[1].subtract(q[0])).mod(P);
        BigInteger b = p[1].add(p[0]).multiply(q[1].add(q[0])).mod(P);
        BigInteger c = p[3].multiply(q[3]).multiply(D).shiftLeft(1).mod(P);
        BigInteger d = p[2].multiply(q[2]).shiftLeft(1).mod(P);
        BigInteger e = b.subtract(a), f = d.subtract(c), g = d.add(c), h = b.add(a);
        return new BigInteger[]{e.multiply(f).mod(P), g.multiply(h).mod(P), f.multiply(g).mod(P), e.multiply(h).mod(P)};
    }

    static BigInteger[] mul(BigInteger s, BigInteger[] p) {
        BigInteger[] r = {BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO};
        for (int i = s.bitLength() - 1; i >= 0; i--) {
            r = add(r, r);
            if (s.testBit(i)) r = add(r, p);
        }
        return r;
    }

    private static BigInteger[] neg(BigInteger[] p) {
        return new BigInteger[]{P.subtract(p[0]).mod(P), p[1], p[2], P.subtract(p[3]).mod(P)};
    }

    static byte[] encode(BigInteger[] p) {
        BigInteger zi = p[2].modInverse(P);
        BigInteger x = p[0].multiply(zi).mod(P), y = p[1].multiply(zi).mod(P);
        byte[] b = toLe(y, 32);
        if (x.testBit(0)) b[31] |= (byte) 0x80;
        return b;
    }

    static BigInteger[] decode(byte[] in) {
        byte[] b = in.clone();
        boolean sign = (b[31] & 0x80) != 0;
        b[31] &= 0x7f;
        BigInteger y = le(b);
        if (y.compareTo(P) >= 0) return null;
        BigInteger y2 = y.multiply(y).mod(P);
        BigInteger x2 = y2.subtract(BigInteger.ONE).multiply(D.multiply(y2).add(BigInteger.ONE).modInverse(P)).mod(P);
        BigInteger x = x2.modPow(P.add(BigInteger.valueOf(3)).shiftRight(3), P);
        if (!x.multiply(x).mod(P).equals(x2)) x = x.multiply(SQRT_M1).mod(P);
        if (!x.multiply(x).mod(P).equals(x2)) return null;
        if (x.testBit(0) != sign) x = P.subtract(x).mod(P);
        return new BigInteger[]{x, y, BigInteger.ONE, x.multiply(y).mod(P)};
    }

    static BigInteger le(byte[] b) {
        byte[] be = new byte[b.length + 1];
        for (int i = 0; i < b.length; i++) be[b.length - i] = b[i];
        return new BigInteger(be);
    }

    static byte[] toLe(BigInteger v, int n) {
        byte[] be = v.toByteArray(), out = new byte[n];
        for (int i = 0; i < n && i < be.length; i++) out[i] = be[be.length - 1 - i];
        return out;
    }

    static byte[] sha512(byte[] b) {
        try { return MessageDigest.getInstance("SHA-512").digest(b); } catch (Exception e) { throw new RuntimeException(e); }
    }

    static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return b;
    }
}
