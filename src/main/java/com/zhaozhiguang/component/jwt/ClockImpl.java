package com.zhaozhiguang.component.jwt;


import com.zhaozhiguang.component.jwt.interfaces.Clock;

import java.util.Date;

final class ClockImpl implements Clock {

    ClockImpl() {
    }

    @Override
    public Date getToday() {
        return new Date();
    }
}
