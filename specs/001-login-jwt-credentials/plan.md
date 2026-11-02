# 구현 계획: AU1 로그인·JWT·자격 교환

**Branch**: `claude/project-thread-tht1mn` | **Date**: 2026-11-02 | **Spec**: [spec.md](./spec.md)

## 요약

auth-server에 토큰 발급 경로 9개(로그인·재발급·로그아웃·내 정보·부스 토큰·페어링 발급/교환·QR 발급/교환)와 JWKS를 만든다. JWT는 Nimbus JOSE로 RS256 서명하고, auth-server 자신의 보호 경로는 같은 공개키로 Spring Security 리소스 서버가 검증한다. 리프레시 토큰은 Redis, 나머지는 PostgreSQL `auth` 스키마(Flyway V1은 docs `db/V1__init.sql` auth 절 그대로, V2는 pairing_code.rental_id).

## 기술 맥락

**Language/Version**: Java 21, Spring Boot 3.5.7, Maven(./mvnw)
**Primary Dependencies**: Spring Web MVC, Spring Data JPA, Flyway(+postgresql 모듈), Spring Security OAuth2 리소스 서버(spring-security-oauth2-jose → Nimbus JOSE), spring-security-crypto BCrypt, Spring Data Redis, Bean Validation, ProblemDetail
**Storage**: PostgreSQL 스키마 `auth`, Redis DB 2(`trace:` 접두사)
**Testing**: JUnit 5, Spring Boot Test, MockMvc, Mockito, Testcontainers(PostgreSQL·Redis), JaCoCo 줄 40%
**Target Platform**: 학교 Rancher 클러스터(파드 1개), 로컬은 compose 폴백(G1)
**Constraints**: 액세스 15분·리프레시 7일·촬영 30분·부스 1시간·AGENT 10분·페어링 코드 5분(설계서 "인증")
**Scale/Scope**: 파일럿 수십 명, 단일 인스턴스

Spring AMQP(trace.events)는 AU1에서 쓰지 않는다(봉인 이벤트 소비는 AU3). 이 기능에는 넣지 않는다.

## 헌법 점검

| 원칙 | 확인 |
| --- | --- |
| I. 계약이 먼저 | 경로·본문·상태·오류 code는 contracts `openapi/auth-server.yaml` 그대로. 계약 변경 없음. pairing_code.rental_id는 계약(PR #4)을 따르는 DB 추가 변경 |
| II. 서비스 경계 | auth 스키마만. rentalId·checkpointId는 값으로만 들고 rental-server에 묻지 않는다 |
| III. 기록 불변 | 해당 없음(기록 없음) |
| IV. 테스트 | 수용 시나리오마다 테스트, 이름은 수용 기준 문장. `./mvnw verify` |
| V. 비밀 | 비밀번호·client secret BCrypt, QR·페어링 SHA-256만 저장, 키·초기 비밀번호는 환경 변수(trace-secrets), 로그에 원문 없음 |
| VI. 단순 | 키 교체(kid 여러 개)는 JWKS 형식만 맞추고 키는 하나만 둔다 |

## 설계

### 패키지 (`com.gakdo.trace.auth`)

```
common/   api(GlobalExceptionHandler, Problems) · domain(AuthException, ErrorCode) · infra(NanoId, Sha256, SecureTokens)
config/   SecurityConfig, AuthProperties(trace.auth.*), ProblemWriters(401·403 본문)
token/    domain(TokenRole, TokenClaims) · application(JwtIssuer) · infra(SigningKeyProvider, RefreshTokenStore, RedisRefreshTokenStore) · api(JwksController)
account/  domain(Account, AccountRepository, RentalAccess, RentalAccessRepository) · application(LoginService, InitialDataLoader) · api(AuthController, DTO)
booth/    domain(ClientCredential, ClientCredentialRepository) · application(BoothTokenService) · api(BoothTokenController)
pairing/  domain(PairingCode, PairingCodeRepository) · application(PairingService) · api(PairingController)
capture/  domain(CaptureLink, CaptureLinkRepository) · application(CaptureLinkService) · api(CaptureLinkController)
```

### 보안

- `JwtDecoder` = `NimbusJwtDecoder.withPublicKey(서명 공개키)` + `iss=trace` 검증.
- 권한 변환: `role` 클레임 → `ROLE_<role>`. 단 `role=CUSTOMER`이면서 `scope` 클레임이 있으면(촬영 JWT) `ROLE_CAPTURE`만 준다. 그래서 `hasAnyRole('ADMIN','CUSTOMER')` 경로는 촬영 JWT를 자연히 403으로 막는다.
- 공개: ping, login, refresh, booth/token, pairing-codes/exchange, jwks, actuator health. ADMIN: capture-links, pairing-codes. CUSTOMER: capture-links/exchange. ADMIN·CUSTOMER: me, logout.
- 401·403은 Problem Details(`UNAUTHENTICATED`·`FORBIDDEN`). CSRF 끔(무상태, 리프레시 쿠키는 SameSite=Strict + Path 한정).

### 토큰

| 토큰 | sub | role | scope | 그 밖 | 수명 |
| --- | --- | --- | --- | --- | --- |
| 액세스(ADMIN) | 계정 publicId | ADMIN | - | - | 900 |
| 액세스(CUSTOMER) | 계정 publicId | CUSTOMER | - | rentals[] | 900 |
| 촬영 | 계정 publicId | CUSTOMER | checkpointId | rentalId | 1800 |
| 부스 | clientId | BOOTH | clientId(boothId) | - | 3600 |
| 에이전트 | checkpointId | AGENT | checkpointId | rentalId | 600 |

공통: `iss=trace`, `iat`, `exp`, `jti`(NanoID 21자), 헤더 `kid`.

리프레시: 32바이트 난수 base64url. Redis `trace:auth:refresh:{sha256}` = 계정 publicId(TTL 7일), `trace:auth:refresh:account:{계정 publicId}` 집합. 쿠키 `trace_refresh; HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth; Max-Age=604800`.

### 설정 (환경 변수)

| 키 | 출처 | 쓰임 |
| --- | --- | --- |
| POSTGRES_HOST·PORT, DB_USERNAME·PASSWORD | infra.env·trace-secrets | 데이터소스(`jdbc:postgresql://…/trace?currentSchema=auth`) |
| REDIS_HOST·PORT·DATABASE·PASSWORD, REDIS_KEY_PREFIX | infra.env·trace-secrets | 리프레시 저장 |
| JWT_PRIVATE_KEY | trace-secrets | PKCS#8 PEM을 base64 한 줄로 |
| ADMIN_EMAIL·ADMIN_PASSWORD | trace-secrets(새 키) | 초기 관리자 |
| BOOTH_CLIENT_ID·BOOTH_CLIENT_SECRET | trace-secrets(새 키) | 초기 부스 자격 |
| WEB_PUBLIC_URL | infra.env(새 키) | QR 링크 주소 앞부분 |

### 테스트 전략

- 단위: JwtIssuer(클레임·kid·서명), SigningKeyProvider(base64 PEM·임시 키), 서비스 4개(Mockito 리포지토리, 고정 Clock).
- 슬라이스: `@WebMvcTest` + 실제 SecurityConfig로 역할·촬영 JWT 403, 오류 본문.
- 통합: `AuthFlowIntegrationTest`(PostgreSQL·Redis). CI는 Testcontainers, 세션은 `TRACE_IT_LOCAL=1`이면 로컬 PostgreSQL·Redis에 붙는다. 둘 다 없으면 건너뛴다.

## Complexity Tracking

| 항목 | 이유 | 더 단순한 안을 버린 이유 |
| --- | --- | --- |
| 통합 테스트가 `disabledWithoutDocker` 대신 "Docker 또는 TRACE_IT_LOCAL" 조건 | 이 세션에는 Docker 데몬은 없지만 PostgreSQL·Redis가 있어 Flyway·JPA를 직접 확인할 수 있다 | `disabledWithoutDocker`만 쓰면 세션에서 DB 매핑을 한 번도 돌려 보지 못하고 CI에서 처음 깨진다. Docker가 없고 변수도 없으면 똑같이 건너뛴다 |
