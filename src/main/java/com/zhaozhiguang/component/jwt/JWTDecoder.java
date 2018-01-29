package com.zhaozhiguang.component.jwt;

import com.zhaozhiguang.component.jwt.exceptions.JWTDecodeException;
import com.zhaozhiguang.component.jwt.interfaces.DecodedJWT;
import com.zhaozhiguang.component.jwt.interfaces.Header;
import com.zhaozhiguang.component.jwt.interfaces.Payload;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

final class JWTDecoder implements DecodedJWT {

    private final String[] parts;
    private final Header header;
    private final Payload payload;

    JWTDecoder(String jwt) throws JWTDecodeException {
        parts = TokenUtils.splitToken(jwt);
        final JWTParser converter = new JWTParser();
        String headerJson;
        String payloadJson;
        try {
            headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]),StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new JWTDecodeException("The UTF-8 Charset isn't initialized.", e);
        }
        header = converter.parseHeader(headerJson);
        payload = converter.parsePayload(payloadJson);
    }

    @Override
    public String getAlgorithm() {
        return header.getAlgorithm();
    }

    @Override
    public String getType() {
        return header.getType();
    }

    @Override
    public String getContentType() {
        return header.getContentType();
    }

    @Override
    public String getKeyId() {
        return header.getKeyId();
    }

    @Override
    public String getIssuer() {
        return payload.getIssuer();
    }

    @Override
    public String getSubject() {
        return payload.getSubject();
    }

    @Override
    public List<String> getAudience() {
        return payload.getAudience();
    }

    @Override
    public Date getExpiresAt() {
        return payload.getExpiresAt();
    }

    @Override
    public Date getNotBefore() {
        return payload.getNotBefore();
    }

    @Override
    public Date getIssuedAt() {
        return payload.getIssuedAt();
    }

    @Override
    public String getId() {
        return payload.getId();
    }

    @Override
    public Map<String, Object> getParameters() {
        return payload.getParameters();
    }

    @Override
    public String getHeader() {
        return parts[0];
    }

    @Override
    public String getPayload() {
        return parts[1];
    }

    @Override
    public String getSignature() {
        return parts[2];
    }

    @Override
    public String getToken() {
        return String.format("%s.%s.%s", parts[0], parts[1], parts[2]);
    }
}
