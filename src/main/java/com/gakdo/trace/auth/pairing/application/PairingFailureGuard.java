package com.gakdo.trace.auth.pairing.application;

/**
 * 페어링 코드 대입 공격을 막는 전역 실패 한도(contracts 1.0.0 exchangePairingCode).
 * 틀린 코드는 어느 코드를 노렸는지 알 수 없어 코드별 한도를 걸 수 없으므로, 모든 클라이언트의 실패를 합쳐 센다.
 */
public interface PairingFailureGuard {

    /** 지금 교환을 막고 있으면 남은 초(1 이상), 아니면 0. */
    long blockedForSeconds();

    /** 틀린 코드 한 번을 센다. 한도를 넘기면 막기 시작한다. */
    void recordFailure();
}
