package com.zhaozhiguang.component.jwt;


import com.zhaozhiguang.component.jwt.algorithms.Algorithm;
import com.zhaozhiguang.component.jwt.exceptions.JWTDecodeException;
import com.zhaozhiguang.component.jwt.interfaces.DecodedJWT;
import com.zhaozhiguang.component.jwt.interfaces.Verification;

public abstract class JWT {

    public static DecodedJWT decode(String token) throws JWTDecodeException {
        return new JWTDecoder(token);
    }

    public static Verification require(Algorithm algorithm) {
        return JWTVerifier.init(algorithm);
    }

    public static JWTCreator.Builder create() {
        return JWTCreator.init();
    }
}
