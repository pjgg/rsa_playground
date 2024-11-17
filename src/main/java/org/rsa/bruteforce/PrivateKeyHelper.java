package org.rsa.bruteforce;

import java.math.BigInteger;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class PrivateKeyHelper {

    // Method to extract primes (p, q) from the private key's modulus 'n' using Pollard's Rho
    public BigInteger[] getPrimesFromPrivateKey(RsaGenerator.RSAKeyPair rsaKeyPair) throws Exception {
        BigInteger n = rsaKeyPair.publicKey.modulus;
        BigInteger d = rsaKeyPair.privateKey.privateExponent;
        int numThreads = Runtime.getRuntime().availableProcessors();

        // Use parallel Pollard's Rho to find a factor of 'n'
        BigInteger factor = findFactorInParallel(n, numThreads);
        if (factor == null) {
            throw new Exception("Failed to find a non-trivial factor.");
        }

        // Calculate the other prime q
        BigInteger p = factor;
        BigInteger q = n.divide(factor);
        System.out.println("Expected private Key primes");
        System.out.println("p: " + p);
        System.out.println("q: " + q);

        // Calculate φ(n) = (p-1)*(q-1)
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        System.out.println("φ(n): " + phi);

        // Print the private exponent 'd'
        System.out.println("Private exponent (d): " + d);

        return new BigInteger[]{p, q};
    }

    // Parallel Pollard's Rho algorithm for factoring a large number 'n'
    private BigInteger findFactorInParallel(BigInteger n, int numThreads) throws InterruptedException, ExecutionException {
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        Future<BigInteger>[] futures = new Future[numThreads];

        for (int i = 0; i < numThreads; i++) {
            final int threadIndex = i;
            futures[i] = executor.submit(() -> pollardRho(n, threadIndex));
        }

        for (Future<BigInteger> future : futures) {
            BigInteger factor = future.get();
            if (factor != null && factor.compareTo(BigInteger.ONE) > 0 && factor.compareTo(n) < 0) {
                executor.shutdown();
                return factor;
            }
        }

        executor.shutdown();
        return null;
    }

    // Pollard's Rho algorithm implementation to find a factor of 'n'
    private BigInteger pollardRho(BigInteger n, int threadIndex) {
        BigInteger x = BigInteger.valueOf(threadIndex + 2);  // Start at different values for x based on thread index
        BigInteger y = x;
        BigInteger d = BigInteger.ONE;

        // Keep running the algorithm until we find a factor
        while (d.equals(BigInteger.ONE)) {
            x = f(x, n);  // x moves one step
            y = f(f(y, n), n);  // y moves two steps (tortoise and hare method)
            d = x.subtract(y).abs().gcd(n);  // GCD of (x - y) and n

            // If we find a non-trivial factor, return it
            if (d.compareTo(BigInteger.ONE) > 0 && d.compareTo(n) < 0) {
                return d;
            }
        }

        return null;
    }

    // Function used in Pollard's Rho: f(z) = (z^2 + 1) mod n
    private BigInteger f(BigInteger z, BigInteger n) {
        return z.multiply(z).add(BigInteger.ONE).mod(n);
    }
}
