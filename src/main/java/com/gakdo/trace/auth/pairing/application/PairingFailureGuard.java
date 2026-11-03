package com.gakdo.trace.auth.pairing.application;

/**
 * 페어링 코드 대입 공격을 막는 전역 실패 한도(contracts 1.0.0 exchangePairingCode).
 * 틀린 코드는 어느 코드를 노렸는지 알 수 없어 코드별 한도를 걸 수 없으므로, 모든 클라이언트의 실패를 합쳐 센다.
 *
 * <p>동시 요청이 한꺼번에 확인을 통과하지 못하도록, 조회 전에 시도 하나를 실패로 먼저 잡아 두고
 * (확인과 증가를 한 번의 원자 연산으로) 코드가 있으면 되돌린다. 그래서 한 창에서 동시에 조회되는 추측도 한도를 넘지 못한다.
 */
public interface PairingFailureGuard {

    /**
     * 시도 하나를 실패로 먼저 잡는다. 받아들이면 0, 막는 중이거나 한도를 넘으면 남은 초(1 이상)를 돌려주고 시도를 거절한다.
     */
    long tryAcquire();

    /** 코드가 실제로 있어 추측이 아니었던 시도를 실패 수에서 되돌린다. */
    void refund();
}
