package org.rsa.bruteforce;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Date;

public class RsaGenerator {

    private final static int KEY_SIZE = 32;

    public static RSAKeyPair generateRSAKeyPair() {
        SecureRandom random = new SecureRandom();

        // Generate 8-bit prime numbers p and q
        BigInteger p = generatePrime(KEY_SIZE, random); // 8 bits for the primes
        BigInteger q;
        do {
            q = generatePrime(KEY_SIZE, random);
        } while (p.equals(q)); // Ensure p != q

        // Calculate n = p * q
        BigInteger n = p.multiply(q);

        // Calculate the totient function, φ(n) = (p-1) * (q-1)
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        // Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1
        BigInteger e = BigInteger.valueOf(3);
        while (phi.gcd(e).compareTo(BigInteger.ONE) > 0) {
            e = e.add(BigInteger.TWO);
        }

        // Calculate the private exponent d
        BigInteger d = e.modInverse(phi);

        // Calculate additional values for the private key (Chinese Remainder Theorem optimization)
        BigInteger exponent1 = d.mod(p.subtract(BigInteger.ONE));
        BigInteger exponent2 = d.mod(q.subtract(BigInteger.ONE));
        BigInteger coefficient = q.modInverse(p);

        // Create public and private keys
        Key publicKey = new Key(e, n);
        Key privateKey = new Key(d, n, d, p, q, exponent1, exponent2, coefficient);  // Use d as privateExponent

        return new RSAKeyPair(publicKey, privateKey);
    }

    private static BigInteger generatePrime(int bitLength, SecureRandom random) {
        BigInteger prime;
        do {
            prime = new BigInteger(bitLength, random).nextProbablePrime();
        } while (prime.bitLength() != bitLength);
        return prime;
    }

    // Save the public key as an X.509 certificate in PEM format
    public static void savePublicKeyAsX509Certificate(Key publicKey, String filePath) throws Exception {
        try {
            X509Certificate cert = generateSelfSignedX509Certificate(publicKey);
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
                JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
                pemWriter.writeObject(cert);
                pemWriter.close();
            }

            System.out.println("Public key saved as X.509 certificate in PEM format.");

        } catch (IOException | GeneralSecurityException e) {
            System.err.println("Error saving public key as X.509 certificate: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // Generate a self-signed X.509 certificate for the RSA public key
    private static X509Certificate generateSelfSignedX509Certificate(Key publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, GeneralSecurityException {
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        X509Name subject = new X509Name("CN=Self-Signed Certificate");
        certGen.setIssuerDN(subject);
        certGen.setSubjectDN(subject);

        // Set the public key
        certGen.setPublicKey(publicKey.toPublicKey());
        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + (365L * 24 * 60 * 60 * 1000)); // 1 year validity
        certGen.setNotBefore(notBefore);
        certGen.setNotAfter(notAfter);

        certGen.setSignatureAlgorithm("SHA256withRSA");
        return certGen.generate(publicKey.toPrivateKey());
    }

    // Save the private key to a file (PKCS#8 or PEM format as needed)
    public static void saveKeyToFile(Key key, String filePath, boolean isPublicKey) {
        try {
            byte[] keyBytes;

            if (isPublicKey) {
                keyBytes = encodePublicKey(key);
            } else {
                keyBytes = convertToPKCS8(key);
            }

            String base64Key = Base64.getEncoder().encodeToString(keyBytes);
            writeKeyToFile(filePath, base64Key, isPublicKey);

            System.out.println(isPublicKey ? "Public key saved to PEM file." : "Private key saved to PEM file.");
        } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            System.err.println("Error saving key to PEM file: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static byte[] encodePublicKey(Key key) {
        // Encode the public key (exponent, modulus)
        return encodeKey(key.exponent, key.modulus);
    }

    private static byte[] encodePrivateKey(Key key) {
        // Encode the private key (exponent, modulus)
        return encodeKey(key.exponent, key.modulus);
    }

    private static byte[] encodeKey(BigInteger exponent, BigInteger modulus) {
        // Combine the exponent and modulus into a byte array
        byte[] expBytes = exponent.toByteArray();
        byte[] modBytes = modulus.toByteArray();

        byte[] keyBytes = new byte[expBytes.length + modBytes.length];
        System.arraycopy(expBytes, 0, keyBytes, 0, expBytes.length);
        System.arraycopy(modBytes, 0, keyBytes, expBytes.length, modBytes.length);

        return keyBytes;
    }

    private static byte[] convertToPKCS8(Key key) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        // Extract the necessary components for the RSAPrivateKey
        BigInteger modulus = key.modulus;
        BigInteger publicExponent = key.exponent; // Public exponent (e)
        BigInteger privateExponent = key.privateExponent; // Private exponent (d)
        BigInteger prime1 = key.prime1; // Prime1 (p)
        BigInteger prime2 = key.prime2; // Prime2 (q)
        BigInteger exponent1 = key.exponent1; // Exponent1 (dp)
        BigInteger exponent2 = key.exponent2; // Exponent2 (dq)
        BigInteger coefficient = key.coefficient; // Coefficient (qInv)

        RSAPrivateKey rsaPrivateKey = new RSAPrivateKey(modulus, publicExponent, privateExponent,
                prime1, prime2, exponent1, exponent2, coefficient);

        return rsaPrivateKey.toASN1Primitive().getEncoded(ASN1Encoding.DER); // Ensure it's DER-encoded
    }

    private static void writeKeyToFile(String filePath, String base64Key, boolean isPublicKey) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            writePEMHeader(writer, isPublicKey);
            writeBase64Key(writer, base64Key);
            writePEMFooter(writer, isPublicKey);
        }
    }

    private static void writePEMHeader(BufferedWriter writer, boolean isPublicKey) throws IOException {
        if (isPublicKey) {
            writer.write("-----BEGIN PUBLIC KEY-----\n");
        } else {
            writer.write("-----BEGIN PRIVATE KEY-----\n");
        }
    }

    private static void writeBase64Key(BufferedWriter writer, String base64Key) throws IOException {
        int chunkSize = 64;
        for (int i = 0; i < base64Key.length(); i += chunkSize) {
            writer.write(base64Key, i, Math.min(chunkSize, base64Key.length() - i));
            writer.newLine();
        }
    }

    private static void writePEMFooter(BufferedWriter writer, boolean isPublicKey) throws IOException {
        if (isPublicKey) {
            writer.write("-----END PUBLIC KEY-----\n");
        } else {
            writer.write("-----END PRIVATE KEY-----\n");
        }
    }

    static class RSAKeyPair {
        Key publicKey;
        Key privateKey;

        public RSAKeyPair(Key publicKey, Key privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }
    }

    static class Key {
        BigInteger exponent;
        BigInteger modulus;
        BigInteger privateExponent;
        BigInteger prime1;
        BigInteger prime2;
        BigInteger exponent1;
        BigInteger exponent2;
        BigInteger coefficient;

        public Key(BigInteger exponent, BigInteger modulus) {
            this.exponent = exponent;
            this.modulus = modulus;
        }

        public Key(BigInteger exponent, BigInteger modulus, BigInteger privateExponent,
                   BigInteger prime1, BigInteger prime2, BigInteger exponent1,
                   BigInteger exponent2, BigInteger coefficient) {
            this.exponent = exponent;
            this.modulus = modulus;
            this.privateExponent = privateExponent; // Use the correct private exponent (d)
            this.prime1 = prime1;
            this.prime2 = prime2;
            this.exponent1 = exponent1;
            this.exponent2 = exponent2;
            this.coefficient = coefficient;
        }

        public PublicKey toPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
            RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePublic(spec);
        }

        public PrivateKey toPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
            RSAPrivateKeySpec spec = new RSAPrivateKeySpec(modulus, privateExponent);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePrivate(spec);
        }

        @Override
        public String toString() {
            return "(" + exponent + ", " + modulus + ")";
        }
    }
}
