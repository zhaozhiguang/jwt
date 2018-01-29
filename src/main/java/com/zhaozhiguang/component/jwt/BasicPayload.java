package com.zhaozhiguang.component.jwt;

import com.alibaba.fastjson.annotation.JSONField;
import com.zhaozhiguang.component.jwt.interfaces.Payload;
import com.zhaozhiguang.component.jwt.interfaces.PublicClaims;

import java.util.Date;
import java.util.List;
import java.util.Map;

public class BasicPayload implements Payload {

    @JSONField(name = PublicClaims.ISSUER)
    private String issuer;

    @JSONField(name = PublicClaims.SUBJECT)
    private String subject;

    @JSONField(name = PublicClaims.AUDIENCE)
    private List<String> audience;

    @JSONField(name = PublicClaims.EXPIRES_AT)
    private Date expiresAt;

    @JSONField(name = PublicClaims.NOT_BEFORE)
    private Date notBefore;

    @JSONField(name = PublicClaims.ISSUED_AT)
    private Date issuedAt;

    @JSONField(name = PublicClaims.JWT_ID)
    private String jwtId;

    @JSONField(name = PublicClaims.PARAMETERS)
    private Map<String, Object> parameters;


    @Override
    public String getIssuer() {
        return issuer;
    }

    @Override
    public String getSubject() {
        return subject;
    }

    @Override
    public List<String> getAudience() {
        return audience;
    }

    @Override
    public Date getExpiresAt() {
        return expiresAt;
    }

    @Override
    public Date getNotBefore() {
        return notBefore;
    }

    @Override
    public Date getIssuedAt() {
        return issuedAt;
    }

    @Override
    public String getId() {
        return jwtId;
    }

    @Override
    public Map<String, Object> getParameters() {
        return parameters;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public void setAudience(List<String> audience) {
        this.audience = audience;
    }

    public void setExpiresAt(Date expiresAt) {
        this.expiresAt = expiresAt;
    }

    public void setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
    }

    public void setIssuedAt(Date issuedAt) {
        this.issuedAt = issuedAt;
    }

    public String getJwtId() {
        return jwtId;
    }

    public void setJwtId(String jwtId) {
        this.jwtId = jwtId;
    }

    public void setParameters(Map<String, Object> parameters) {
        this.parameters = parameters;
    }
}
