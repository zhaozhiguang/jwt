package com.zhaozhiguang.component.jwt.interfaces;

import java.util.Date;
import java.util.List;
import java.util.Map;

public interface Payload {

    String getIssuer();

    String getSubject();

    List<String> getAudience();

    Date getExpiresAt();

    Date getNotBefore();

    Date getIssuedAt();

    String getId();

    Map<String, Object> getParameters();
}
