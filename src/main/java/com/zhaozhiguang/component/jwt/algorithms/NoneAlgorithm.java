package com.zhaozhiguang.component.jwt.algorithms;

import com.zhaozhiguang.component.jwt.exceptions.SignatureGenerationException;
import com.zhaozhiguang.component.jwt.exceptions.SignatureVerificationException;
import com.zhaozhiguang.component.jwt.interfaces.DecodedJWT;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

class NoneAlgorithm extends Algorithm {

    NoneAlgorithm() {
        super("none", "none");
    }

    @Override
    public void verify(DecodedJWT jwt) throws SignatureVerificationException {
        byte[] signatureBytes = Base64.getDecoder().decode(jwt.getSignature().getBytes(StandardCharsets.UTF_8));
        if (signatureBytes.length > 0) {
            throw new SignatureVerificationException(this);
        }
    }

    @Override
    public byte[] sign(byte[] contentBytes) throws SignatureGenerationException {
        return new byte[0];
    }
}
