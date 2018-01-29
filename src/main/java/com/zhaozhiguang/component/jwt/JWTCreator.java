package com.zhaozhiguang.component.jwt;

import com.alibaba.fastjson.JSON;
import com.zhaozhiguang.component.jwt.algorithms.Algorithm;
import com.zhaozhiguang.component.jwt.exceptions.JWTCreationException;
import com.zhaozhiguang.component.jwt.exceptions.SignatureGenerationException;
import com.zhaozhiguang.component.jwt.interfaces.PublicClaims;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public final class JWTCreator {

    private final Algorithm algorithm;
    private final String headerJson;
    private final String payloadJson;

    private JWTCreator(Algorithm algorithm, Map<String, Object> headerClaims, Map<String, Object> payloadClaims) throws JWTCreationException {
        this.algorithm = algorithm;
        headerJson = JSON.toJSONString(headerClaims);
        payloadJson = JSON.toJSONString(payloadClaims);
    }


    static JWTCreator.Builder init() {
        return new Builder();
    }

    public static class Builder {
        private Map<String, Object> payloadClaims;
        private Map<String, Object> headerClaims;

        Builder() {
            this.payloadClaims = new HashMap<>();
            this.headerClaims = new HashMap<>();
        }

        public Builder withHeader(Map<String, Object> headerClaims) {
            this.headerClaims = new HashMap<>(headerClaims);
            return this;
        }

        public Builder withKeyId(String keyId) {
            this.headerClaims.put(PublicClaims.KEY_ID, keyId);
            return this;
        }

        public Builder withIssuer(String issuer) {
            addClaim(PublicClaims.ISSUER, issuer);
            return this;
        }

        public Builder withSubject(String subject) {
            addClaim(PublicClaims.SUBJECT, subject);
            return this;
        }

        public Builder withAudience(String... audience) {
            addClaim(PublicClaims.AUDIENCE, audience);
            return this;
        }

        public Builder withExpiresAt(Date expiresAt) {
            addClaim(PublicClaims.EXPIRES_AT, expiresAt);
            return this;
        }

        public Builder withNotBefore(Date notBefore) {
            addClaim(PublicClaims.NOT_BEFORE, notBefore);
            return this;
        }

        public Builder withIssuedAt(Date issuedAt) {
            addClaim(PublicClaims.ISSUED_AT, issuedAt);
            return this;
        }

        public Builder withJWTId(String jwtId) {
            addClaim(PublicClaims.JWT_ID, jwtId);
            return this;
        }

        public Builder withParameters(Map<String, Object> param) throws IllegalArgumentException {
            payloadClaims.put(PublicClaims.PARAMETERS,param);
            return this;
        }

        public Builder withClaim(String name, Boolean value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        public Builder withClaim(String name, Integer value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        public Builder withClaim(String name, Long value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        public Builder withClaim(String name, Double value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        public Builder withClaim(String name, String value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        public Builder withClaim(String name, Date value) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, value);
            return this;
        }

        public Builder withArrayClaim(String name, String[] items) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, items);
            return this;
        }

        public Builder withArrayClaim(String name, Integer[] items) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, items);
            return this;
        }

        public Builder withArrayClaim(String name, Long[] items) throws IllegalArgumentException {
            assertNonNull(name);
            addClaim(name, items);
            return this;
        }

        public String sign(Algorithm algorithm) throws IllegalArgumentException, JWTCreationException {
            if (algorithm == null) {
                throw new IllegalArgumentException("The Algorithm cannot be null.");
            }
            headerClaims.put(PublicClaims.ALGORITHM, algorithm.getName());
            headerClaims.put(PublicClaims.TYPE, "JWT");
            String signingKeyId = algorithm.getSigningKeyId();
            if (signingKeyId != null) {
                withKeyId(signingKeyId);
            }
            return new JWTCreator(algorithm, headerClaims, payloadClaims).sign();
        }

        private void assertNonNull(String name) {
            if (name == null) {
                throw new IllegalArgumentException("The Custom Claim's name can't be null.");
            }
        }

        private void addClaim(String name, Object value) {
            if (value == null) {
                payloadClaims.remove(name);
                return;
            }
            payloadClaims.put(name, value);
        }
    }

    private String sign() throws SignatureGenerationException {
        String header = Base64.getUrlEncoder().encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));
        String content = String.format("%s.%s", header, payload);
        byte[] signatureBytes = algorithm.sign(content.getBytes(StandardCharsets.UTF_8));
        String signature = Base64.getUrlEncoder().encodeToString(signatureBytes);
        return String.format("%s.%s", content, signature);
    }
}
