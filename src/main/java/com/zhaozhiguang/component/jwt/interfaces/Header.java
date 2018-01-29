package com.zhaozhiguang.component.jwt.interfaces;

public interface Header {

    String getAlgorithm();

    String getType();

    String getContentType();

    String getKeyId();

}
