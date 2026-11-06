package com.gakdo.trace.auth.account.application;

import com.gakdo.trace.auth.account.domain.EmailTokenPurpose;

/** 같은 이메일·용도의 코드 메일을 60초에 한 번으로 묶는다(Redis). */
public interface ResendGuard {

    /** 보내도 되면 0을 돌려주고 창을 연다. 아직 창 안이면 남은 초를 돌려준다. */
    long tryAcquire(EmailTokenPurpose purpose, String normalizedEmail);
}
