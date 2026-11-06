# AU2 고객 가입·이메일 인증·비밀번호 재설정·탈퇴

백로그: AU2 · 요구사항: FR-USR-01, FR-USR-04, FR-USR-05, FR-USR-06 · 계약: contracts `openapi/auth-server.yaml`(경로·오류 코드 그대로, 변경 없음)

## 수용 기준

| 요구사항 | 기준 | 테스트 |
| --- | --- | --- |
| FR-USR-01 | 동의 없이 가입하면 400 CONSENT_REQUIRED, 같은 이메일이면 409 EMAIL_ALREADY_EXISTS | AccountLifecycleTest.consentAndDuplicate |
| FR-USR-05 | 가입하면 PENDING + 6자리 코드 메일, 코드는 SHA-256만 저장, 인증 전 로그인 403 | AccountLifecycleTest.signupThenVerify, AccountFlowIntegrationTest |
| FR-USR-05 | 코드는 10분 뒤 만료, 5번 틀리면 폐기(410), 틀릴 때마다 남은 횟수(remainingAttempts) | AccountLifecycleTest.attemptsAndExpiry |
| FR-USR-05 | 재발송은 60초에 한 번(429 RESEND_TOO_SOON + Retry-After), 새 코드를 보내면 앞 코드는 무효 | AccountLifecycleTest.resendReplacesAndThrottles, SecurityRulesTest.codeProblems |
| FR-USR-06 | 없는 이메일도 같은 응답(202), 재설정하면 리프레시 토큰 전부 폐기 | AccountLifecycleTest.unknownEmailIsSilent·resetPassword |
| FR-USR-04 | 탈퇴는 CUSTOMER만, 비밀번호 확인 뒤 이메일·이름·비밀번호를 지우고 WITHDRAWN, 렌탈 기록은 남김 | AccountLifecycleTest.withdrawAccount, SecurityRulesTest.withdrawIsCustomerOnly, AccountFlowIntegrationTest |

## 설계 메모

- 테이블은 V1의 `auth.email_token`(purpose VERIFY·RESET)을 그대로 쓴다. 새 마이그레이션 없음.
- 메일은 Spring Mail(팀 Gmail SMTP). 환경 변수 `SMTP_HOST`·`SMTP_PORT`(infra.env), `SMTP_USERNAME`·`SMTP_PASSWORD`(trace-secrets/.env), 보내는 주소 `SMTP_FROM`(없으면 SMTP_USERNAME). SMTP_HOST가 비면 보내지 않고 경고만 남긴다. 메일은 DB 커밋 뒤에 보낸다.
- 재발송 창은 Redis `trace:auth:email-resend:{용도}:{이메일 SHA-256}`(SET NX EX 60). Redis가 안 되면 막지 않는다.
- 없는 이메일·고객이 아닌 계정의 인증·재설정은 코드가 없는 것과 같이 410으로 답한다(가입 여부를 드러내지 않음).
- 메일 헬스 체크는 끈다(SMTP가 잠깐 안 돼도 프로브가 실패하지 않게).
