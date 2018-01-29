package com.zhaozhiguang.component.jwt.algorithms;

import com.zhaozhiguang.component.jwt.exceptions.SignatureGenerationException;
import com.zhaozhiguang.component.jwt.exceptions.SignatureVerificationException;
import com.zhaozhiguang.component.jwt.interfaces.DecodedJWT;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

class HMACAlgorithm extends Algorithm {

    private final CryptoHelper crypto;
    private final byte[] secret;

    HMACAlgorithm(CryptoHelper crypto, String id, String algorithm, byte[] secretBytes) throws IllegalArgumentException {
        super(id, algorithm);
        if (secretBytes == null) {
            throw new IllegalArgumentException("The Secret cannot be null");
        }
        this.secret = secretBytes;
        this.crypto = crypto;
    }

    HMACAlgorithm(String id, String algorithm, byte[] secretBytes) throws IllegalArgumentException {
        this(new CryptoHelper(), id, algorithm, secretBytes);
    }

    HMACAlgorithm(String id, String algorithm, String secret) throws IllegalArgumentException, UnsupportedEncodingException {
        this(new CryptoHelper(), id, algorithm, getSecretBytes(secret));
    }

    static byte[] getSecretBytes(String secret) throws IllegalArgumentException, UnsupportedEncodingException {
        if (secret == null) {
            throw new IllegalArgumentException("The Secret cannot be null");
        }
        return secret.getBytes("utf-8");
    }

    @Override
    public void verify(DecodedJWT jwt) throws SignatureVerificationException {
        byte[] contentBytes = String.format("%s.%s", jwt.getHeader(), jwt.getPayload()).getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = Base64.getUrlDecoder().decode(jwt.getSignature().getBytes(StandardCharsets.UTF_8));

        try {
            boolean valid = crypto.verifySignatureFor(getDescription(), secret, contentBytes, signatureBytes);
            if (!valid) {
                throw new SignatureVerificationException(this);
            }
        } catch (IllegalStateException | InvalidKeyException | NoSuchAlgorithmException e) {
            throw new SignatureVerificationException(this, e);
        }
    }

    @Override
    public byte[] sign(byte[] contentBytes) throws SignatureGenerationException {
        try {
            return crypto.createSignatureFor(getDescription(), secret, contentBytes);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new SignatureGenerationException(this, e);
        }
    }

}
