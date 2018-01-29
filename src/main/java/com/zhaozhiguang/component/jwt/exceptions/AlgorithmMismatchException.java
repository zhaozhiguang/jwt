package com.zhaozhiguang.component.jwt.exceptions;

public class AlgorithmMismatchException extends JWTVerificationException {

    public AlgorithmMismatchException(String message) {
        super(message);
    }
}
