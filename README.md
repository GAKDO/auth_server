# auth-server

TRACE(노트북 렌탈 상태 기록 서비스)의 **auth-server**: 회원가입·로그인·이메일 인증·소셜 로그인(구글·깃허브, 카카오·네이버는 키를 넣으면)·비밀번호 재설정·탈퇴·자격 교환·QR 링크·페어링 코드·JWKS·봉인 영수증 메일

- 담당: A
- 설계: [GAKDO/docs](https://github.com/GAKDO/docs) — 요구사항·아키텍처·ERD·REST API v0
- 기술: Java 21, Spring Boot 3.5.7, Maven

## 실행

```bash
./mvnw spring-boot:run
```

```bash
curl http://localhost:8080/api/v1/auth/ping
```

로컬은 PostgreSQL(DB `trace`)과 Redis가 필요합니다. Flyway가 `auth` 스키마를 만듭니다.

## API

계약 원본: GAKDO/contracts `openapi/auth-server.yaml`. 아래는 요약입니다.

| 경로 | 하는 일 |
|---|---|
| `POST /api/v1/auth/signup`·`/login`·`/refresh`·`/logout` | 이메일 가입·로그인. 액세스 토큰(RS256)과 리프레시 토큰(Redis) |
| `POST /api/v1/auth/email/verify`·`/email/resend` | 이메일 인증 코드 확인·재발송 |
| `POST /api/v1/auth/password/reset-request`·`/password/reset` | 비밀번호 재설정 코드 메일, 6자리 코드로 재설정 |
| `GET /api/v1/auth/me`, `DELETE /api/v1/auth/me` | 내 정보, 탈퇴(비밀번호 확인. 소셜 가입자는 로그인한 지 10분 안이면 비밀번호 없이) |
| `GET /api/v1/auth/oauth/providers`, `GET /api/v1/auth/oauth/{provider}/start`·`/callback` | 소셜 로그인(서버 리다이렉트 방식). 이메일을 꼭 받고, 키를 넣은 제공자만 보이며, 고객(CUSTOMER) 계정만 만든다 |
| `POST /api/v1/auth/capture-links`, `POST /api/v1/auth/capture-links/exchange` | 수령 QR 링크 만들기, QR 토큰을 렌탈 범위 토큰으로 교환(QR 토큰은 SHA-256 해시만 저장) |
| `POST /api/v1/auth/pairing-codes`, `POST /api/v1/auth/pairing-codes/exchange` | 진단 페어링 코드 만들기, 에이전트 토큰으로 교환 |
| `POST /api/v1/auth/booth/token` | 부스 자격(client id·secret, BCrypt)으로 부스 JWT 발급 |
| `GET /.well-known/jwks.json` | JWT 공개 키(gateway·서버가 검증에 씀) |

`trace.events`의 `record.sealed`를 받으면 고객에게 봉인 영수증 메일(검증 링크)을 보냅니다. 로그인·가입·코드 확인·재설정은 gateway가 IP당 분당 10회로 막습니다.

## 환경 변수

| 키 | 출처 | 쓰임 |
|---|---|---|
| `POSTGRES_HOST`·`POSTGRES_PORT`·`POSTGRES_DB`, `DB_USERNAME`·`DB_PASSWORD` | trace-infra·trace-secrets | `auth` 스키마 |
| `RABBITMQ_HOST`·`RABBITMQ_PORT`·`RABBITMQ_VHOST`·`RABBITMQ_USERNAME`·`RABBITMQ_PASSWORD` | trace-infra·trace-secrets | `trace.events`(봉인 영수증 메일) |
| `REDIS_HOST`·`REDIS_PORT`·`REDIS_DATABASE`·`REDIS_PASSWORD`, `REDIS_KEY_PREFIX` | trace-infra·trace-secrets | 리프레시 토큰(`trace:auth:refresh:*`) |
| `JWT_PRIVATE_KEY` | trace-secrets | RS256 서명 키. PKCS#8 PEM을 한 줄로: `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \| base64 -w0`. `school` 프로필은 없으면 시작하지 않고, 로컬은 임시 키를 만든다 |
| `ADMIN_EMAIL`·`ADMIN_PASSWORD` | trace-secrets | 초기 관리자(없을 때만 만듦) |
| `BOOTH_CLIENT_ID`·`BOOTH_CLIENT_SECRET` | trace-secrets | 부스 자격(없을 때만 만듦, ID는 32자 이하 = boothId) |
| `WEB_PUBLIC_URL` | trace-infra | QR 링크·메일 링크·소셜 로그인 콜백 주소 앞부분(기본 `http://localhost:8315`, 운영 `https://gakdo.site`) |
| `GOOGLE_CLIENT_ID`·`GOOGLE_CLIENT_SECRET`, `GITHUB_…`, `KAKAO_…`, `NAVER_…` | trace-secrets | 소셜 로그인. 비우면 그 제공자 버튼이 숨는다. 제공자 앱에 등록할 콜백은 `{WEB_PUBLIC_URL}/api/v1/auth/oauth/{google\|github\|kakao\|naver}/callback` |
| `SMTP_HOST`·`SMTP_PORT`(587)·`SMTP_USERNAME`·`SMTP_PASSWORD`·`SMTP_FROM` | trace-infra·trace-secrets | 인증·재설정 코드와 봉인 영수증 메일(팀 Gmail SMTP). 비우면 보내지 않고 로그만 남긴다 |
| `DEMO_CUSTOMER_EMAIL`·`DEMO_CUSTOMER_PASSWORD` | trace-secrets | 시연용 고객 계정(없을 때만 만듦) |

## 테스트

```bash
./mvnw verify
```

줄 커버리지 40% 미만이면 실패합니다(블로그와 같은 기준). 통합 테스트(`AuthFlowIntegrationTest`)는 Docker가 있으면 Testcontainers로 돌고, Docker가 없는 환경에서는 `TRACE_IT_LOCAL=1`이면 로컬 PostgreSQL의 테스트 전용 DB(`localhost:5432/trace_it`, 사용자 postgres, 먼저 `createdb -U postgres trace_it`)·Redis(`localhost:6379`, DB 15)에 붙습니다. 개발 DB `trace`는 건드리지 않습니다. 둘 다 없으면 건너뜁니다.

## CI/CD

| 워크플로 | 언제 | 하는 일 |
|---|---|---|
| `backend-ci` | PR, develop push | 테스트 + JaCoCo 40% + (켜져 있으면) 학교 SonarQube |
| `배포` | PR(빌드만), develop·main push(`.md`만 바뀌면 건너뜀) | 이미지 → GHCR(`ghcr.io/<조직>/auth-server`, develop은 `:develop`). 지금 운영(https://gakdo.site, 학교 서버 Compose)은 gitops `compose/ops/autodeploy.sh`가 3분마다 `:develop`을 받아 이 서비스만 무중단으로 바꾼다. main이면 gitops `overlays/school` 이미지 태그도 바꾼다(클러스터 경로, 지금은 쓰지 않음) |
| `비밀값 검사` | PR, main·develop push | 학교 공용 비밀번호 패턴 + gitleaks |
| `release` | main에 CHANGELOG 버전 | 태그와 GitHub Release |
| `PR 알림`·`CI 결과 알림` | PR·CI 끝 | Discord·텔레그램 (변수로 켬) |

브랜치 규칙과 릴리스 절차는 [CONTRIBUTING.md](CONTRIBUTING.md)에 있습니다.
