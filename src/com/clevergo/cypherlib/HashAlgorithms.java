package com.clevergo.cypherlib;

public enum HashAlgorithms {
    MD2("MD2"),
    MD5("MD5"),
    SHA("SHA"),
    SHA1("SHA-1"),
    SHA224("SHA-224"),
    SHA256("SHA-256"),
    SHA384("SHA-384"),
    SHA512("SHA-512"),
    SHA3224("SHA3-224"),
    SHA3256("SHA3-256"),
    SHA3384("SHA3-384"),
    SHA3512("SHA3-512");


    private final String algorithm;

    HashAlgorithms(final String algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public String toString() {
        return algorithm;
    }
}
