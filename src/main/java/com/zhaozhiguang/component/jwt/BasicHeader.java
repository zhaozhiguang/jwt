package com.zhaozhiguang.component.jwt;

import com.alibaba.fastjson.annotation.JSONField;
import com.zhaozhiguang.component.jwt.interfaces.Header;
import com.zhaozhiguang.component.jwt.interfaces.PublicClaims;

public class BasicHeader implements Header {

    @JSONField(name = PublicClaims.ALGORITHM)
    private String algorithm;

    @JSONField(name = PublicClaims.TYPE)
    private String type;

    @JSONField(name = PublicClaims.CONTENT_TYPE)
    private String contentType;

    @JSONField(name = PublicClaims.KEY_ID)
    private String keyId;

    public BasicHeader() {
    }

    public BasicHeader(String algorithm, String type, String contentType, String keyId) {
        this.algorithm = algorithm;
        this.type = type;
        this.contentType = contentType;
        this.keyId = keyId;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getType() {
        return type;
    }

    @Override
    public String getContentType() {
        return contentType;
    }

    @Override
    public String getKeyId() {
        return keyId;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public void setType(String type) {
        this.type = type;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }
}
