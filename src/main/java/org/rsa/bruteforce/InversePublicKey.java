package org.rsa.bruteforce;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.*;

public class InversePublicKey {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private RSAPublicKey getRawPublicKey(String publicKeyPem) throws InvalidKeySpecException, NoSuchAlgorithmException {
        String cleanedKey = cleanPemKey(publicKeyPem);
        byte[] decodedKey = Base64.getDecoder().decode(cleanedKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    private BigInteger getModulusN(RSAPublicKey publicKey) {
        return publicKey.getModulus();
    }

    private BigInteger getPublicExponent(RSAPublicKey publicKey) {
        return publicKey.getPublicExponent();
    }

    public static BigInteger[] factorizeRSA(BigInteger n) throws InterruptedException, ExecutionException {
        BigInteger[] primes = new BigInteger[2];
        BigInteger sqrtN = n.sqrt();

        int numThreads = Runtime.getRuntime().availableProcessors();
        BigInteger rangeSize = sqrtN.divide(BigInteger.valueOf(numThreads));

        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        List<Callable<BigInteger[]>> tasks = new ArrayList<>();

        for (int i = 0; i < numThreads; i++) {
            final BigInteger start = BigInteger.valueOf(i).multiply(rangeSize).add(BigInteger.TWO);
            final BigInteger end = (i == numThreads - 1) ? sqrtN : start.add(rangeSize);

            tasks.add(() -> findFactorInRange(n, start, end));
        }

        List<Future<BigInteger[]>> results = executor.invokeAll(tasks);
        for (Future<BigInteger[]> result : results) {
            BigInteger[] factorPair = result.get();
            if (factorPair != null) {
                primes[0] = factorPair[0];
                primes[1] = factorPair[1];
                executor.shutdownNow();
                return primes;
            }
        }

        executor.shutdown();
        throw new ArithmeticException("No factor found");
    }

    private static BigInteger[] findFactorInRange(BigInteger n, BigInteger start, BigInteger end) {
        for (BigInteger factor = start; factor.compareTo(end) <= 0; factor = factor.add(BigInteger.ONE)) {
            if (n.mod(factor).equals(BigInteger.ZERO)) {
                return new BigInteger[]{factor, n.divide(factor)};
            }
        }
        return null;
    }

    public String getPrivateKey(BigInteger n, BigInteger e, boolean encodeKey) throws ExecutionException, InterruptedException, NoSuchAlgorithmException, InvalidKeySpecException {
        System.out.println("ModulusN size: " + n.bitLength());
        System.out.println("Public exponent: " + e);

        // Factor the modulus 'n' using Pollard's Rho
        BigInteger[] primes = factorizeRSA(n);
        BigInteger p = primes[0];
        BigInteger q = primes[1];
        System.out.println("Generated private Key primes from public Key");
        System.out.println("Factor p: " + p);
        System.out.println("Factor q: " + q);

        // Calculate φ(n) = (p - 1) * (q - 1)
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        System.out.println("φ(n): " + phi);

        // Calculate the private exponent 'd' (modular inverse of e mod φ(n))
        BigInteger d = e.modInverse(phi);
        System.out.println("Calculated private exponent (d): " + d);

        // Verify that d * e % φ(n) == 1
        System.out.println("Check d * e % φ(n): " + d.multiply(e).mod(phi));
        String privateKeyAsString = "";
        if(encodeKey) {
            RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(n, d);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
            byte[] privateKeyBytes = privateKey.getEncoded();
            privateKeyAsString =  Base64.getEncoder().encodeToString(privateKeyBytes);
        }

        return privateKeyAsString;
    }

    public String getPrivateKey(String publicKey, boolean encodeKey) throws InvalidKeySpecException, NoSuchAlgorithmException, ExecutionException, InterruptedException {
        RSAPublicKey rawPublicKey = getRawPublicKey(publicKey);
        BigInteger n = getModulusN(rawPublicKey);
        BigInteger e = getPublicExponent(rawPublicKey);
        return getPrivateKey(n, e, encodeKey);
    }

    // Function to be used in Pollard's Rho algorithm: f(z) = (z^2 + 1) mod n
    public static BigInteger f(BigInteger z, BigInteger n) {
        return z.multiply(z).add(BigInteger.ONE).mod(n);
    }

    private String cleanPemKey(String pemKey) {
        String cleanedKey = pemKey.replaceAll("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("-----END PUBLIC KEY-----", "")
                .replaceAll("[\\n\\r]+", "")
                .trim();

        System.out.println("Cleaned Key: " + cleanedKey);

        return cleanedKey;
    }
}
