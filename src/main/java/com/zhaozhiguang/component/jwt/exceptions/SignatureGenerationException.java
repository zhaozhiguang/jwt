package com.zhaozhiguang.component.jwt.exceptions;


import com.zhaozhiguang.component.jwt.algorithms.Algorithm;

public class SignatureGenerationException extends JWTCreationException {

    public SignatureGenerationException(Algorithm algorithm, Throwable cause) {
        super("The Token's Signature couldn't be generated when signing using the Algorithm: " + algorithm, cause);
    }
}
