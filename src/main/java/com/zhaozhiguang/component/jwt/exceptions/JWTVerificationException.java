package com.zhaozhiguang.component.jwt.exceptions;

public class JWTVerificationException extends RuntimeException {

    public JWTVerificationException(String message) {
        this(message, null);
    }

    public JWTVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
