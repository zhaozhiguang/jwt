package com.zhaozhiguang.component.jwt;

import com.alibaba.fastjson.JSON;
import com.zhaozhiguang.component.jwt.exceptions.JWTDecodeException;
import com.zhaozhiguang.component.jwt.interfaces.Header;
import com.zhaozhiguang.component.jwt.interfaces.JWTPartsParser;
import com.zhaozhiguang.component.jwt.interfaces.Payload;

public class JWTParser implements JWTPartsParser {

    @Override
    public Payload parsePayload(String json) throws JWTDecodeException {
        return convertFromJSON(json, BasicPayload.class);
    }

    @Override
    public Header parseHeader(String json) throws JWTDecodeException {
        return convertFromJSON(json, BasicHeader.class);
    }

    <T> T convertFromJSON(String json, Class<T> tClazz) throws JWTDecodeException {
        if (json == null) {
            throw exceptionForInvalidJson(null);
        }
        return JSON.parseObject(json, tClazz);
    }

    private JWTDecodeException exceptionForInvalidJson(String json) {
        return new JWTDecodeException(String.format("The string '%s' doesn't have a valid JSON format.", json));
    }
}
