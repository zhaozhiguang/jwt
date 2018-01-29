package com.zhaozhiguang.component.jwt.interfaces;

public interface DecodedJWT extends Payload, Header {

    String getToken();

    String getHeader();

    String getPayload();

    String getSignature();
}
