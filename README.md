# auth-server

TRACE(노트북 렌탈 상태 기록 서비스)의 **auth-server**: 회원가입·로그인·이메일 인증·자격 교환·QR 링크·페어링 코드·JWKS·봉인 영수증 메일

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

## 환경 변수

| 키 | 출처 | 쓰임 |
|---|---|---|
| `POSTGRES_HOST`·`POSTGRES_PORT`, `DB_USERNAME`·`DB_PASSWORD` | trace-infra·trace-secrets | `auth` 스키마 |
| `REDIS_HOST`·`REDIS_PORT`·`REDIS_DATABASE`·`REDIS_PASSWORD`, `REDIS_KEY_PREFIX` | trace-infra·trace-secrets | 리프레시 토큰(`trace:auth:refresh:*`) |
| `JWT_PRIVATE_KEY` | trace-secrets | RS256 서명 키. PKCS#8 PEM을 한 줄로: `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \| base64 -w0`. `school` 프로필은 없으면 시작하지 않고, 로컬은 임시 키를 만든다 |
| `ADMIN_EMAIL`·`ADMIN_PASSWORD` | trace-secrets | 초기 관리자(없을 때만 만듦) |
| `BOOTH_CLIENT_ID`·`BOOTH_CLIENT_SECRET` | trace-secrets | 부스 자격(없을 때만 만듦, ID는 32자 이하 = boothId) |
| `WEB_PUBLIC_URL` | trace-infra | QR 링크 주소 앞부분(기본 `http://localhost:8315`) |

## 테스트

```bash
./mvnw verify
```

줄 커버리지 40% 미만이면 실패합니다(블로그와 같은 기준). 통합 테스트(`AuthFlowIntegrationTest`)는 Docker가 있으면 Testcontainers로 돌고, Docker가 없는 환경에서는 `TRACE_IT_LOCAL=1`이면 로컬 PostgreSQL의 테스트 전용 DB(`localhost:5432/trace_it`, 사용자 postgres, 먼저 `createdb -U postgres trace_it`)·Redis(`localhost:6379`, DB 15)에 붙습니다. 개발 DB `trace`는 건드리지 않습니다. 둘 다 없으면 건너뜁니다.

## CI/CD

| 워크플로 | 언제 | 하는 일 |
|---|---|---|
| `backend-ci` | PR, develop push | 테스트 + JaCoCo 40% + (켜져 있으면) 학교 SonarQube |
| `배포` | PR(빌드만), develop·main push | 이미지 → GHCR(`ghcr.io/<조직>/auth-server`). main이면 gitops 레포 이미지 태그 갱신 → Argo CD 배포 |
| `비밀값 검사` | PR, main·develop push | 학교 공용 비밀번호 패턴 + gitleaks |
| `release` | main에 CHANGELOG 버전 | 태그와 GitHub Release |
| `PR 알림`·`CI 결과 알림` | PR·CI 끝 | Discord·텔레그램 (변수로 켬) |

브랜치 규칙과 릴리스 절차는 [CONTRIBUTING.md](CONTRIBUTING.md)에 있습니다.
