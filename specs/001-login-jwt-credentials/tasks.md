# 작업: AU1 로그인·JWT·자격 교환

입력: [spec.md](./spec.md), [plan.md](./plan.md), [data-model.md](./data-model.md). `[P]`는 다른 파일이라 함께 해도 되는 작업, `[US1]`~`[US4]`는 명세의 사용자 이야기.

## 1단계: 준비

- [x] T001 pom.xml에 data-jpa·postgresql·flyway(+database-postgresql)·oauth2-resource-server·data-redis·testcontainers(postgresql) 더하기
- [x] T002 application.yml: 데이터소스·Flyway(스키마 auth)·Redis·`trace.auth.*`(수명·쿠키·WEB_PUBLIC_URL)·초기 데이터 환경 변수
- [x] T003 [P] `db/migration/V1__auth_init.sql`(docs V1 auth 절 그대로), `V2__pairing_code_rental_id.sql`

## 2단계: 기반 (모든 이야기의 전제)

- [x] T004 [P] common: `NanoId`, `Sha256`, `SecureTokens`(난수 토큰·6자리 코드)
- [x] T005 [P] common: `ErrorCode`(codes.yaml error_code 중 AU1이 쓰는 값)·`AuthException`·`GlobalExceptionHandler`(Problem Details + code, 검증 오류 400 VALIDATION_FAILED)
- [x] T006 token: `SigningKeyProvider`(base64 PEM, 없으면 school 외 임시 키, kid = RFC 7638 지문)
- [x] T007 token: `JwtIssuer`(iss·sub·role·scope·rentals·rentalId·iat·exp·jti, 헤더 kid)
- [x] T008 config: `SecurityConfig`(공개 경로, 역할 규칙, CUSTOMER+scope → ROLE_CAPTURE, 401·403 Problem 본문)
- [x] T009 엔티티·리포지토리 5개(Account, RentalAccess, ClientCredential, CaptureLink, PairingCode)

## 3단계: 이야기 4 — JWKS (P1)

- [x] T010 [US4] 테스트: JWKS가 RSA·sig·RS256·kid를 주고 발급 JWT가 그 키로 검증된다
- [x] T011 [US4] `JwksController` `GET /.well-known/jwks.json`

## 4단계: 이야기 1 — 로그인·재발급 (P1)

- [x] T012 [US1] 테스트: 로그인 200·쿠키 속성, 틀리면 401, PENDING 403, rentals 클레임, 리프레시 교체·재사용 401, 로그아웃 뒤 401, 만료 토큰 401, /me
- [x] T013 [US1] `RefreshTokenStore` + `RedisRefreshTokenStore`
- [x] T014 [US1] `LoginService`(login·refresh·logout·me), `AuthController`, DTO
- [x] T015 [US1] `InitialDataLoader`(ADMIN_EMAIL·ADMIN_PASSWORD, BOOTH_CLIENT_ID·BOOTH_CLIENT_SECRET)

## 5단계: 이야기 3 — 부스·페어링 (P1)

- [x] T016 [P] [US3] 테스트: 부스 토큰 200·401, 페어링 발급 201·해시만 저장, 교환 200·재사용 410·5분 뒤 410·없는 코드 400
- [x] T017 [US3] `BoothTokenService`·`BoothTokenController`
- [x] T018 [US3] `PairingService`·`PairingController`(같은 해시 유효 코드 재추첨, 조건부 갱신)

## 6단계: 이야기 2 — QR 링크 (P1)

- [x] T019 [US2] 테스트: 발급 201·해시만 저장, 교환 200·연결, 사용·만료 410, 다른 계정 409, 촬영 JWT로 /me 403
- [x] T020 [US2] `CaptureLinkService`·`CaptureLinkController`

## 7단계: 마무리

- [x] T021 통합 테스트 `AuthFlowIntegrationTest`(PostgreSQL·Redis, CI Testcontainers / 세션 TRACE_IT_LOCAL)
- [x] T022 `./mvnw verify` 통과(JaCoCo 40%), `scripts/check-no-secrets.sh`
- [x] T023 README 환경 변수 표, docs ddl.md(pairing_code.rental_id)·decisions.md·board 갱신

## 의존 관계

1·2단계 → 3~6단계(서로 독립, 같은 SecurityConfig 사용) → 7단계.
