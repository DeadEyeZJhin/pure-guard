package local.pureguard;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

// Pure-Java pieces of the adb client (PC-tested by test/Spake2Test.java): the public key in
// adb's own format, a self-signed TLS certificate, the legacy USB auth signature, and HKDF.
final class AdbKeys {
    private AdbKeys() {}

    // android_pubkey_encode + base64 + " name": what adbd stores in adb_keys.
    static String pubKey(RSAPublicKey k, String name) {
        BigInteger n = k.getModulus(), two32 = BigInteger.ONE.shiftLeft(32);
        java.nio.ByteBuffer b = java.nio.ByteBuffer.allocate(524).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        b.putInt(64);
        b.putInt(n.mod(two32).modInverse(two32).negate().mod(two32).intValue()); // n0inv = -1/n mod 2^32
        b.put(Spake2.toLe(n, 256));
        b.put(Spake2.toLe(BigInteger.ONE.shiftLeft(4096).mod(n), 256)); // rr = (2^2048)^2 mod n
        b.putInt(k.getPublicExponent().intValue());
        return Base64.getEncoder().encodeToString(b.array()) + " " + name;
    }

    // Legacy (USB) auth: PKCS#1 v1.5 signature of the 20-byte token as if it were a SHA-1 digest.
    static byte[] signToken(KeyPair k, byte[] token) throws Exception {
        byte[] prefix = Spake2.hex("3021300906052b0e03021a05000414");
        byte[] di = new byte[prefix.length + token.length];
        System.arraycopy(prefix, 0, di, 0, prefix.length);
        System.arraycopy(token, 0, di, prefix.length, token.length);
        Signature s = Signature.getInstance("NONEwithRSA");
        s.initSign(k.getPrivate());
        s.update(di);
        return s.sign();
    }

    // Minimal self-signed X.509 (adbd checks only the public key, never the name or dates).
    static X509Certificate cert(KeyPair k) throws Exception {
        byte[] alg = der(0x30, der(0x06, Spake2.hex("2a864886f70d01010b")), der(0x05)); // sha256WithRSA
        byte[] name = der(0x30, der(0x31, der(0x30, der(0x06, Spake2.hex("550403")), der(0x0c, "Pure Guard".getBytes("UTF-8")))));
        byte[] tbs = der(0x30,
                der(0xa0, der(0x02, new byte[]{2})),           // v3
                der(0x02, new byte[]{1}),                       // serial
                alg, name,
                der(0x30, der(0x17, "200101000000Z".getBytes("US-ASCII")), der(0x17, "491231235959Z".getBytes("US-ASCII"))),
                name,
                k.getPublic().getEncoded());
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(k.getPrivate());
        s.update(tbs);
        byte[] sig = s.sign(), bits = new byte[sig.length + 1];
        System.arraycopy(sig, 0, bits, 1, sig.length);
        byte[] cert = der(0x30, tbs, alg, der(0x03, bits));
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(cert));
    }

    private static byte[] der(int tag, byte[]... parts) {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (byte[] p : parts) body.write(p, 0, p.length);
        int n = body.size();
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(tag);
        if (n < 128) o.write(n);
        else if (n < 256) { o.write(0x81); o.write(n); }
        else { o.write(0x82); o.write(n >> 8); o.write(n); }
        o.write(body.toByteArray(), 0, n);
        return o.toByteArray();
    }

    // HKDF-SHA256 with an empty salt (same as 32 zero bytes), one output block.
    static byte[] hkdf(byte[] ikm, String info, int len) throws Exception {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
        byte[] prk = m.doFinal(ikm);
        m.init(new SecretKeySpec(prk, "HmacSHA256"));
        m.update(info.getBytes("UTF-8"));
        m.update((byte) 1);
        return java.util.Arrays.copyOf(m.doFinal(), len);
    }
}
