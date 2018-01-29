package com.zhaozhiguang.component.jwt;


import com.zhaozhiguang.component.jwt.exceptions.JWTDecodeException;

abstract class TokenUtils {

    static String[] splitToken(String token) throws JWTDecodeException {
        String[] parts = token.split("\\.");
        if (parts.length == 2 && token.endsWith(".")) {
            parts = new String[]{parts[0], parts[1], ""};
        }
        if (parts.length != 3) {
            throw new JWTDecodeException(String.format("The token was expected to have 3 parts, but got %s.", parts.length));
        }
        return parts;
    }
}
