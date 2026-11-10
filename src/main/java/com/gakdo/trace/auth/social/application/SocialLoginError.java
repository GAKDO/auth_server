package com.gakdo.trace.auth.social.application;

/**
 * 소셜 로그인 실패 사유. 콜백은 JSON이 아니라 웹 로그인 화면으로 돌려보내므로
 * /login?socialError=<값> 으로 실어 보낸다(contracts auth-server.yaml 콜백 설명과 같은 값).
 */
public enum SocialLoginError {
    /** 서버에 그 제공자의 키가 설정되지 않음 */
    UNAVAILABLE,
    /** 사용자가 제공자 화면에서 취소함 */
    CANCELLED,
    /** state가 없거나 만료됐거나 이 브라우저에서 시작한 로그인이 아님 */
    STATE_INVALID,
    /** 제공자가 인증된 이메일을 주지 않음(이메일 제공 동의 안 함·미인증 이메일) */
    EMAIL_REQUIRED,
    /** 제공자 통신 실패 */
    PROVIDER_ERROR
}
