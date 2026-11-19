package local.pureguard;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

// PC self-test of the wireless-debugging pairing crypto: Ed25519 math against RFC 8032 and the
// numbers printed in BoringSSL's spake25519.cc, SPAKE2 agreement, and the adb key/cert helpers.
public class Spake2Test {
    static int fails;

    static void check(String what, boolean ok) {
        System.out.println((ok ? "ok   " : "FAIL ") + what);
        if (!ok) fails++;
    }

    public static void main(String[] a) throws Exception {
        // M and N: coordinates from the spake25519.cc comment, and re-derived from its seeds.
        check("M x", Spake2.M[0].equals(new BigInteger("31406539342727633121250288103050113562375374900226415211311216773867585644232")));
        check("M y", Spake2.M[1].equals(new BigInteger("21177308356423958466833845032658859666296341766942662650232962324899758529114")));
        check("N x", Spake2.N[0].equals(new BigInteger("49918732221787544735331783592030787422991506689877079631459872391322455579424")));
        check("N y", Spake2.N[1].equals(new BigInteger("54629554431565467720832445949441049581317094546788069926228343916274969994000")));
        check("M from seed", Arrays.equals(genpoint("edwards25519 point generation seed (M)"), Spake2.encode(Spake2.M)));
        check("N from seed", Arrays.equals(genpoint("edwards25519 point generation seed (N)"), Spake2.encode(Spake2.N)));

        // RFC 8032 test 1: secret key -> public key exercises mul(B) and encode.
        byte[] h = Spake2.sha512(Spake2.hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"));
        byte[] s = Arrays.copyOf(h, 32);
        s[0] &= (byte) 248; s[31] &= 127; s[31] |= 64;
        check("RFC 8032 public key", Arrays.equals(Spake2.encode(Spake2.mul(Spake2.le(s), Spake2.B)),
                Spake2.hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")));
        check("l*B = identity", Arrays.equals(Spake2.encode(Spake2.mul(Spake2.L, Spake2.B)), Spake2.encode(
                new BigInteger[]{BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO})));

        byte[] cn = "adb pair client\0".getBytes("UTF-8"), sn = "adb pair server\0".getBytes("UTF-8");
        SecureRandom r = new SecureRandom();
        for (int i = 0; i < 5; i++) {
            byte[] pw = ("12345" + i).getBytes("UTF-8");
            Spake2 al = new Spake2(true, cn, sn), bo = new Spake2(false, sn, cn);
            byte[] ma = al.msg(pw, r), mb = bo.msg(pw, r);
            check("same password -> same key #" + i, Arrays.equals(al.key(mb), bo.key(ma)));
        }
        Spake2 al = new Spake2(true, cn, sn), bo = new Spake2(false, sn, cn);
        byte[] ma = al.msg("111111".getBytes(), r), mb = bo.msg("222222".getBytes(), r);
        check("wrong password -> different key", !Arrays.equals(al.key(mb), bo.key(ma)));

        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair k = g.generateKeyPair();
        String pub = AdbKeys.pubKey((RSAPublicKey) k.getPublic(), "pureguard");
        byte[] raw = java.util.Base64.getDecoder().decode(pub.split(" ")[0]);
        java.nio.ByteBuffer bb = java.nio.ByteBuffer.wrap(raw).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        int words = bb.getInt(), n0inv = bb.getInt();
        BigInteger n = ((RSAPublicKey) k.getPublic()).getModulus();
        check("adb key size 524, 64 words", raw.length == 524 && words == 64);
        check("adb key n0inv", n.multiply(BigInteger.valueOf(n0inv & 0xffffffffL)).add(BigInteger.ONE).mod(BigInteger.ONE.shiftLeft(32)).signum() == 0);
        check("adb key modulus", Spake2.le(Arrays.copyOfRange(raw, 8, 264)).equals(n));
        java.security.cert.X509Certificate c = AdbKeys.cert(k);
        c.verify(k.getPublic());
        check("self-signed cert parses and verifies", c.getPublicKey().equals(k.getPublic()));
        byte[] tok = new byte[20];
        r.nextBytes(tok);
        // The token is signed as if it were a digest: undo the RSA and look at the padded block.
        BigInteger sig = new BigInteger(1, AdbKeys.signToken(k, tok));
        byte[] em = sig.modPow(((RSAPublicKey) k.getPublic()).getPublicExponent(), n).toByteArray();
        check("token signature = PKCS#1 SHA-1 DigestInfo", Arrays.equals(Arrays.copyOfRange(em, em.length - 20, em.length), tok)
                && em[0] == 1 && em[em.length - 36] == 0);
        // RFC 5869 test case 3 (empty salt, empty info) checks the HKDF shape.
        check("HKDF RFC 5869 #3", Arrays.equals(AdbKeys.hkdf(Spake2.hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), "", 16),
                Spake2.hex("8da4e775a563c18f715f802a063c5a31")));

        System.out.println(fails == 0 ? "ALL PASSED" : fails + " FAILED");
        System.exit(fails == 0 ? 0 : 1);
    }

    // genpoint() from the Python in spake25519.cc.
    static byte[] genpoint(String seed) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] v = sha.digest(seed.getBytes("UTF-8"));
        while (true) {
            BigInteger[] pt = Spake2.decode(v); // same accept/reject as ed25519.py's decodepoint
            if (pt != null) return Spake2.encode(pt);
            v = sha.digest(v);
        }
    }
}
