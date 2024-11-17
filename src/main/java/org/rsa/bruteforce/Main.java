package org.rsa.bruteforce;

public class Main {

    public static void main(String[] args) throws Exception {
        var keyPair = RsaGenerator.generateRSAKeyPair();
        RsaGenerator.saveKeyToFile(keyPair.privateKey, "src/main/resources/privateKey", false);
        RsaGenerator.saveKeyToFile(keyPair.publicKey, "src/main/resources/publicKey.pub", true);

        InversePublicKey cracker = new InversePublicKey();
        PrivateKeyHelper privateHelper = new PrivateKeyHelper();
        privateHelper.getPrimesFromPrivateKey(keyPair);

        // String privateKey = cracker.getPrivateKey(FileUtils.loadFile("/publicKey.pub"));
        String privateKey = cracker.getPrivateKey(keyPair.publicKey.modulus, keyPair.publicKey.exponent, false);
        System.out.println(privateKey);
    }
}
