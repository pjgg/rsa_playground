# RSA Playground

This project is a playground that tries to calculate the RSA private Key from a public key.
This process involves factoring the modulus into two primes and using the RSA formula to compute the private exponent d.

## Key Concepts

1. **Public Key:** The public key is represented by two values, n (the modulus) and e (the public exponent).
2. **Private Key:** The private key is derived from n, e, and the totient function φ(n). It is typically represented by the private exponent d.

## Workflow

The key generation process proceeds in two parts:

1. Generation of RSA Key Pair:

* Two "large" (32 bits) prime numbers `p` and `q` are generated.
* The modulus `n` is calculated as the product of `p` and `q`.
* The totient function ` φ(n) = (p-1)*(q-1)` is calculated.
* The public exponent `e` is chosen such that `1 < e < φ(n)` and `gcd(e, φ(n)) = 1`.
* The private exponent `d` is calculated as the modular inverse of `e` modulo `φ(n)`

2. Recovery of the Private Key from the Public Key:

* Using the public key (specifically the modulus `n` and public exponent `e`), the modulus `n` is factorized into its prime factors `p` and `q`.
* Once the primes are found, the totient `φ(n)` is computed.
* The private exponent `d` is then derived as the modular inverse of e modulo `φ(n)`.
* The private key is then reconstructed using `n` and `d`.

```shell
Expected private Key primes

p: 211
q: 223
φ(n): 46620
Private exponent (d): 21191


ModulusN size: 16
Public exponent: 11

Generated private Key primes from public Key
Factor p: 211
Factor q: 223
φ(n): 46620
Calculated private exponent (d): 21191
Check d * e % φ(n): 1
```

## Conclusion

This project demonstrates how to generate RSA key pairs and then recover the private key from the public key by factoring the modulus and calculating the private exponent. The factorization of the modulus is achieved using Pollard's Rho algorithm with parallel processing to speed up the computation.

**However, it's important to note that if the RSA key is large enough (typically 2048 bits or more), it becomes practically impossible to recover the private key using a traditional computer**. The factorization of large RSA moduli is computationally intensive, requiring significant CPU resources and time. Even with advanced parallelization techniques and optimized algorithms like Pollard’s Rho, recovering the private key for large key sizes would take an infeasible amount of time on conventional hardware. This is why RSA with sufficiently large key sizes remains secure for most applications, as the required computational effort to break the encryption is beyond the capabilities of everyday computers.