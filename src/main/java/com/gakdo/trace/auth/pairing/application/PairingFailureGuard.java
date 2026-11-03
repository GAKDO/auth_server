package com.gakdo.trace.auth.pairing.application;

/**
 * 페어링 코드 대입 공격을 막는 전역 실패 한도(contracts 1.0.0 exchangePairingCode).
 * 틀린 코드는 어느 코드를 노렸는지 알 수 없어 코드별 한도를 걸 수 없으므로, 모든 클라이언트의 실패를 합쳐 센다.
 *
 * <p>동시 요청이 한꺼번에 확인을 통과하지 못하도록 조회 전에 시도 하나를 "조회 중"으로 원자적으로 잡는다.
 * 한 창에서 확인된 실패 + 조회 중인 시도가 한도에 닿으면 새 시도는 잠깐 거절한다.
 * 막기(1분 차단)는 확인된 실패가 한도에 닿을 때만 시작한다. 조회 중 수만으로는 막지 않는다.
 */
public interface PairingFailureGuard {

    /** 시도 하나를 잡는다. {@link Attempt#blockedForSeconds()}가 0보다 크면 거절된 시도다. */
    Attempt tryAcquire();

    /** 없는 코드였다. 잡아 둔 시도를 확인된 실패로 바꾸고, 한도에 닿으면 막기 시작한다. */
    void recordFailure(Attempt attempt);

    /** 있는 코드였다(추측이 아니다). 잡아 둔 시도를 풀기만 한다. */
    void refund(Attempt attempt);

    /**
     * 잡은 시도. window는 잡을 때 쓴 창(분 경계를 넘어도 같은 창을 풀도록 들고 다닌다). Redis를 못 쓰면 null.
     */
    record Attempt(long blockedForSeconds, String window) {

        public static Attempt allowed(String window) {
            return new Attempt(0, window);
        }

        public static Attempt rejected(long seconds) {
            return new Attempt(seconds, null);
        }
    }
}
