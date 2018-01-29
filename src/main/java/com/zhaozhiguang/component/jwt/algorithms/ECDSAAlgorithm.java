package com.zhaozhiguang.component.jwt.algorithms;

import com.zhaozhiguang.component.jwt.exceptions.SignatureGenerationException;
import com.zhaozhiguang.component.jwt.exceptions.SignatureVerificationException;
import com.zhaozhiguang.component.jwt.interfaces.DecodedJWT;
import com.zhaozhiguang.component.jwt.interfaces.ECDSAKeyProvider;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;

class ECDSAAlgorithm extends Algorithm {

    private final ECDSAKeyProvider keyProvider;
    private final CryptoHelper crypto;
    private final int ecNumberSize;

    ECDSAAlgorithm(CryptoHelper crypto, String id, String algorithm, int ecNumberSize, ECDSAKeyProvider keyProvider) throws IllegalArgumentException {
        super(id, algorithm);
        if (keyProvider == null) {
            throw new IllegalArgumentException("The Key Provider cannot be null.");
        }
        this.keyProvider = keyProvider;
        this.crypto = crypto;
        this.ecNumberSize = ecNumberSize;
    }

    ECDSAAlgorithm(String id, String algorithm, int ecNumberSize, ECDSAKeyProvider keyProvider) throws IllegalArgumentException {
        this(new CryptoHelper(), id, algorithm, ecNumberSize, keyProvider);
    }

    @Override
    public void verify(DecodedJWT jwt) throws SignatureVerificationException {
        byte[] contentBytes = String.format("%s.%s", jwt.getHeader(), jwt.getPayload()).getBytes(StandardCharsets.UTF_8);
        byte[] signatureBytes = Base64.getUrlDecoder().decode(jwt.getSignature().getBytes(StandardCharsets.UTF_8));

        try {
            ECPublicKey publicKey = keyProvider.getPublicKeyById(jwt.getKeyId());
            if (publicKey == null) {
                throw new IllegalStateException("The given Public Key is null.");
            }
            boolean valid = crypto.verifySignatureFor(getDescription(), publicKey, contentBytes, JOSEToDER(signatureBytes));

            if (!valid) {
                throw new SignatureVerificationException(this);
            }
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | IllegalStateException e) {
            throw new SignatureVerificationException(this, e);
        }
    }

    @Override
    public byte[] sign(byte[] contentBytes) throws SignatureGenerationException {
        try {
            ECPrivateKey privateKey = keyProvider.getPrivateKey();
            if (privateKey == null) {
                throw new IllegalStateException("The given Private Key is null.");
            }
            byte[] signature = crypto.createSignatureFor(getDescription(), privateKey, contentBytes);
            return DERToJOSE(signature);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | IllegalStateException e) {
            throw new SignatureGenerationException(this, e);
        }
    }

    @Override
    public String getSigningKeyId() {
        return keyProvider.getPrivateKeyId();
    }

    byte[] DERToJOSE(byte[] derSignature) throws SignatureException {
        boolean derEncoded = derSignature[0] == 0x30 && derSignature.length != ecNumberSize * 2;
        if (!derEncoded) {
            throw new SignatureException("Invalid DER signature format.");
        }

        final byte[] joseSignature = new byte[ecNumberSize * 2];

        int offset = 1;
        if (derSignature[1] == (byte) 0x81) {
            offset++;
        }

        int encodedLength = derSignature[offset++] & 0xff;
        if (encodedLength != derSignature.length - offset) {
            throw new SignatureException("Invalid DER signature format.");
        }

        offset++;

        int rLength = derSignature[offset++];
        if (rLength > ecNumberSize + 1) {
            throw new SignatureException("Invalid DER signature format.");
        }
        int rPadding = ecNumberSize - rLength;
        System.arraycopy(derSignature, offset + Math.max(-rPadding, 0), joseSignature, Math.max(rPadding, 0), rLength + Math.min(rPadding, 0));

        offset += rLength + 1;

        int sLength = derSignature[offset++];
        if (sLength > ecNumberSize + 1) {
            throw new SignatureException("Invalid DER signature format.");
        }
        int sPadding = ecNumberSize - sLength;
        System.arraycopy(derSignature, offset + Math.max(-sPadding, 0), joseSignature, ecNumberSize + Math.max(sPadding, 0), sLength + Math.min(sPadding, 0));

        return joseSignature;
    }

    byte[] JOSEToDER(byte[] joseSignature) throws SignatureException {
        if (joseSignature.length != ecNumberSize * 2) {
            throw new SignatureException("Invalid JOSE signature format.");
        }

        int rPadding = countPadding(joseSignature, 0, ecNumberSize);
        int sPadding = countPadding(joseSignature, ecNumberSize, joseSignature.length);
        int rLength = ecNumberSize - rPadding;
        int sLength = ecNumberSize - sPadding;

        int length = 2 + rLength + 2 + sLength;
        if (length > 255) {
            throw new SignatureException("Invalid JOSE signature format.");
        }

        final byte[] derSignature;
        int offset;
        if (length > 0x7f) {
            derSignature = new byte[3 + length];
            derSignature[1] = (byte) 0x81;
            offset = 2;
        } else {
            derSignature = new byte[2 + length];
            offset = 1;
        }

        derSignature[0] = (byte) 0x30;
        derSignature[offset++] = (byte) (length & 0xff);

        derSignature[offset++] = (byte) 0x02;
        derSignature[offset++] = (byte) rLength;

        if (rPadding < 0) {
            derSignature[offset++] = (byte) 0x00;
            System.arraycopy(joseSignature, 0, derSignature, offset, ecNumberSize);
            offset += ecNumberSize;
        } else {
            int copyLength = Math.min(ecNumberSize, rLength);
            System.arraycopy(joseSignature, rPadding, derSignature, offset, copyLength);
            offset += copyLength;
        }

        derSignature[offset++] = (byte) 0x02;
        derSignature[offset++] = (byte) sLength;

        if (sPadding < 0) {
            derSignature[offset++] = (byte) 0x00;
            System.arraycopy(joseSignature, ecNumberSize, derSignature, offset, ecNumberSize);
        } else {
            System.arraycopy(joseSignature, ecNumberSize + sPadding, derSignature, offset, Math.min(ecNumberSize, sLength));
        }

        return derSignature;
    }

    private int countPadding(byte[] bytes, int fromIndex, int toIndex) {
        int padding = 0;
        while (fromIndex + padding < toIndex && bytes[fromIndex + padding] == 0) {
            padding++;
        }
        return (bytes[fromIndex + padding] & 0xff) > 0x7f ? padding - 1 : padding;
    }

    static ECDSAKeyProvider providerForKeys(final ECPublicKey publicKey, final ECPrivateKey privateKey) {
        if (publicKey == null && privateKey == null) {
            throw new IllegalArgumentException("Both provided Keys cannot be null.");
        }
        return new ECDSAKeyProvider() {
            @Override
            public ECPublicKey getPublicKeyById(String keyId) {
                return publicKey;
            }

            @Override
            public ECPrivateKey getPrivateKey() {
                return privateKey;
            }

            @Override
            public String getPrivateKeyId() {
                return null;
            }
        };
    }
}
