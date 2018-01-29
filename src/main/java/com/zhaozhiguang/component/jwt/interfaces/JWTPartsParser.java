package com.zhaozhiguang.component.jwt.interfaces;


import com.zhaozhiguang.component.jwt.exceptions.JWTDecodeException;

public interface JWTPartsParser {

    Payload parsePayload(String json) throws JWTDecodeException;

    Header parseHeader(String json) throws JWTDecodeException;
}
