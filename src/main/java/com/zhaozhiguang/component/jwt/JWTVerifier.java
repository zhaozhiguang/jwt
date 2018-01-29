package com.zhaozhiguang.component.jwt;


import com.zhaozhiguang.component.jwt.algorithms.Algorithm;
import com.zhaozhiguang.component.jwt.exceptions.AlgorithmMismatchException;
import com.zhaozhiguang.component.jwt.exceptions.InvalidClaimException;
import com.zhaozhiguang.component.jwt.exceptions.JWTVerificationException;
import com.zhaozhiguang.component.jwt.exceptions.TokenExpiredException;
import com.zhaozhiguang.component.jwt.interfaces.Clock;
import com.zhaozhiguang.component.jwt.interfaces.DecodedJWT;
import com.zhaozhiguang.component.jwt.interfaces.PublicClaims;
import com.zhaozhiguang.component.jwt.interfaces.Verification;

import java.util.*;

public final class JWTVerifier {
    private final Algorithm algorithm;
    final Map<String, Object> claims;
    private final Clock clock;

    JWTVerifier(Algorithm algorithm, Map<String, Object> claims, Clock clock) {
        this.algorithm = algorithm;
        this.claims = Collections.unmodifiableMap(claims);
        this.clock = clock;
    }

    static Verification init(Algorithm algorithm) throws IllegalArgumentException {
        return new BaseVerification(algorithm);
    }

    public static class BaseVerification implements Verification {
        private final Algorithm algorithm;
        private final Map<String, Object> claims;
        private long defaultLeeway;

        BaseVerification(Algorithm algorithm) throws IllegalArgumentException {
            if (algorithm == null) {
                throw new IllegalArgumentException("The Algorithm cannot be null.");
            }

            this.algorithm = algorithm;
            this.claims = new HashMap<>();
            this.defaultLeeway = 0;
        }

        @Override
        public Verification withIssuer(String issuer) {
            requireClaim(PublicClaims.ISSUER, issuer);
            return this;
        }

        @Override
        public Verification withSubject(String subject) {
            requireClaim(PublicClaims.SUBJECT, subject);
            return this;
        }

        @Override
        public Verification withAudience(String... audience) {
            requireClaim(PublicClaims.AUDIENCE, Arrays.asList(audience));
            return this;
        }

        @Override
        public Verification acceptLeeway(long leeway) throws IllegalArgumentException {
            assertPositive(leeway);
            this.defaultLeeway = leeway;
            return this;
        }

        @Override
        public Verification acceptExpiresAt(long leeway) throws IllegalArgumentException {
            assertPositive(leeway);
            requireClaim(PublicClaims.EXPIRES_AT, leeway);
            return this;
        }

        @Override
        public Verification acceptNotBefore(long leeway) throws IllegalArgumentException {
            assertPositive(leeway);
            requireClaim(PublicClaims.NOT_BEFORE, leeway);
            return this;
        }

        @Override
        public Verification acceptIssuedAt(long leeway) throws IllegalArgumentException {
            assertPositive(leeway);
            requireClaim(PublicClaims.ISSUED_AT, leeway);
            return this;
        }

        @Override
        public Verification withJWTId(String jwtId) {
            requireClaim(PublicClaims.JWT_ID, jwtId);
            return this;
        }

        @Override
        public Verification withParameters(Map<String, Object> param){
            requireClaim(PublicClaims.PARAMETERS, param);
            return this;
        }

        @Override
        public Verification withClaim(String name, Boolean value) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, value);
            return this;
        }

        @Override
        public Verification withClaim(String name, Integer value) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, value);
            return this;
        }

        @Override
        public Verification withClaim(String name, Long value) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, value);
            return this;
        }

        @Override
        public Verification withClaim(String name, Double value) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, value);
            return this;
        }

        @Override
        public Verification withClaim(String name, String value) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, value);
            return this;
        }

        @Override
        public Verification withClaim(String name, Date value) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, value);
            return this;
        }

        @Override
        public Verification withArrayClaim(String name, String... items) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, items);
            return this;
        }

        @Override
        public Verification withArrayClaim(String name, Integer... items) throws IllegalArgumentException {
            assertNonNull(name);
            requireClaim(name, items);
            return this;
        }

        @Override
        public JWTVerifier build() {
            return this.build(new ClockImpl());
        }

        public JWTVerifier build(Clock clock) {
            addLeewayToDateClaims();
            return new JWTVerifier(algorithm, claims, clock);
        }

        private void assertPositive(long leeway) {
            if (leeway < 0) {
                throw new IllegalArgumentException("Leeway value can't be negative.");
            }
        }

        private void assertNonNull(String name) {
            if (name == null) {
                throw new IllegalArgumentException("The Custom Claim's name can't be null.");
            }
        }

        private void addLeewayToDateClaims() {
            if (!claims.containsKey(PublicClaims.EXPIRES_AT)) {
                claims.put(PublicClaims.EXPIRES_AT, defaultLeeway);
            }
            if (!claims.containsKey(PublicClaims.NOT_BEFORE)) {
                claims.put(PublicClaims.NOT_BEFORE, defaultLeeway);
            }
            if (!claims.containsKey(PublicClaims.ISSUED_AT)) {
                claims.put(PublicClaims.ISSUED_AT, defaultLeeway);
            }
        }

        private void requireClaim(String name, Object value) {
            if (value == null) {
                claims.remove(name);
                return;
            }
            claims.put(name, value);
        }
    }

    public DecodedJWT verify(String token) throws JWTVerificationException {
        DecodedJWT jwt = JWT.decode(token);
        verifyAlgorithm(jwt, algorithm);
        algorithm.verify(jwt);
        verifyClaims(jwt, claims);
        return jwt;
    }

    private void verifyAlgorithm(DecodedJWT jwt, Algorithm expectedAlgorithm) throws AlgorithmMismatchException {
        if (!expectedAlgorithm.getName().equals(jwt.getAlgorithm())) {
            throw new AlgorithmMismatchException("The provided Algorithm doesn't match the one defined in the JWT's Header.");
        }
    }

    private void verifyClaims(DecodedJWT jwt, Map<String, Object> claims) throws TokenExpiredException, InvalidClaimException {
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            switch (entry.getKey()) {
                case PublicClaims.AUDIENCE:
                    assertValidAudienceClaim(jwt.getAudience(), (List<String>) entry.getValue());
                    break;
                case PublicClaims.EXPIRES_AT:
                    assertValidDateClaim(jwt.getExpiresAt(), (Long) entry.getValue(), true);
                    break;
                case PublicClaims.ISSUED_AT:
                    assertValidDateClaim(jwt.getIssuedAt(), (Long) entry.getValue(), false);
                    break;
                case PublicClaims.NOT_BEFORE:
                    assertValidDateClaim(jwt.getNotBefore(), (Long) entry.getValue(), false);
                    break;
                case PublicClaims.ISSUER:
                    assertValidStringClaim(entry.getKey(), jwt.getIssuer(), (String) entry.getValue());
                    break;
                case PublicClaims.JWT_ID:
                    assertValidStringClaim(entry.getKey(), jwt.getId(), (String) entry.getValue());
                    break;
                case PublicClaims.SUBJECT:
                    assertValidStringClaim(entry.getKey(), jwt.getSubject(), (String) entry.getValue());
                    break;
                case PublicClaims.PARAMETERS:
                    assertValidParametersClaim(jwt.getParameters(), (Map<String, Object>) entry.getValue());
                    break;
                default:
                    break;
            }
        }
    }

    private void assertValidParametersClaim(Map<String, Object> jwtParam, Map<String, Object> parameters) {
        if(!jwtParam.equals(parameters)){
            throw new InvalidClaimException(String.format("The parameters value doesn't match the required one."));
        }

    }

    private void assertValidStringClaim(String claimName, String value, String expectedValue) {
        if (!expectedValue.equals(value)) {
            throw new InvalidClaimException(String.format("The Claim '%s' value doesn't match the required one.", claimName));
        }
    }

    private void assertValidDateClaim(Date date, long leeway, boolean shouldBeFuture) {
        Date today = clock.getToday();
        today.setTime((long) Math.floor((today.getTime() / 1000) * 1000)); // truncate millis
        if (shouldBeFuture) {
            assertDateIsFuture(date, leeway, today);
        } else {
            assertDateIsPast(date, leeway, today);
        }
    }

    private void assertDateIsFuture(Date date, long leeway, Date today) {
        today.setTime(today.getTime() - leeway * 1000);
        if (date != null && today.after(date)) {
            throw new TokenExpiredException(String.format("The Token has expired on %s.", date));
        }
    }

    private void assertDateIsPast(Date date, long leeway, Date today) {
        today.setTime(today.getTime() + leeway * 1000);
        if (date != null && today.before(date)) {
            throw new InvalidClaimException(String.format("The Token can't be used before %s.", date));
        }
    }

    private void assertValidAudienceClaim(List<String> audience, List<String> value) {
        if (audience == null || !audience.containsAll(value)) {
            throw new InvalidClaimException("The Claim 'aud' value doesn't contain the required audience.");
        }
    }
}
