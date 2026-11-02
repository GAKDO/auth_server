# 기능 명세: AU1 로그인·JWT·자격 교환

**Feature Branch**: `claude/project-thread-tht1mn` (Spec Kit 기본값은 `feature/001-login-jwt-credentials`, 이 세션의 지정 브랜치를 씀)

**Created**: 2026-11-02

**Status**: Converged

**Backlog**: AU1 (담당 A, 마감 11/5) · 요구사항 FR-AUTH-01, FR-AUTH-02 (QR 교환의 렌탈 연결은 FR-USR-02, QR 발급은 FR-RNT-04)

**Input**: "관리자와 고객이 이메일·비밀번호로 로그인해 액세스 토큰(JWT RS256, 15분)과 리프레시 토큰(7일)을 받고, 부스(client_id·secret)·고객(QR 1회용 토큰)·에이전트(페어링 코드)가 각자의 자격을 범위가 좁은 JWT로 바꾼다. JWKS를 공개한다(FR-AUTH-01, FR-AUTH-02). 수용 기준: 만료된 액세스 토큰은 401이고 리프레시로 다시 발급된다. 고객 JWT로 다른 시점에 접근하면 403이다. 페어링 코드는 5분 뒤 만료되고 SHA-256 해시만 저장한다. 관리자 계정은 초기 데이터로 만든다. 참고: design/mvp-design.md "인증", design/rest-api-v0.md auth 절."

계약 원본: GAKDO/contracts `openapi/auth-server.yaml`(develop, C1 PR #1·#4), `codes.yaml` 0.4.0 `auth.*`·`error_code`.

## Clarifications

### Session 2026-11-02

사용자 지시("묻지 말고 진행, 정할 것만 모아 보고")에 따라 아래는 추천안으로 정하고 PR·보고에 적었다.

- Q: AU1과 AU2·AU3의 경계는? → A: AU1은 토큰을 만드는 모든 경로(로그인·재발급·로그아웃·내 정보, 부스 토큰, 페어링 코드 발급·교환, QR 링크 발급·교환과 렌탈 연결, JWKS)를 맡는다. QR 교환은 발급 없이 시험할 수 없어 QR 발급(FR-RNT-04)도 여기서 만든다. AU2는 가입·이메일 인증·재설정·탈퇴, AU3는 봉인 영수증 메일만 남는다.
- Q: 리프레시 토큰은 어디에 두나? → A: 설계서대로 Redis. 토큰 원문은 브라우저 쿠키에만 있고, 서버는 `trace:auth:refresh:{jti}`(jti = 원문의 SHA-256)에 계정 publicId를 7일 TTL로 둔다. 계정별 집합 `trace:auth:refresh:account:{accountId}`도 두어 AU2 재설정 때 한 번에 지운다. 쓰면 지우고 새로 준다(교체). 지운 토큰을 다시 내면 401 REFRESH_INVALID.
- Q: 서명 키 형식은? → A: `JWT_PRIVATE_KEY`(trace-secrets) = PKCS#8 PEM을 `base64 -w0`로 한 줄로 만든 값. `kid`는 공개키의 RFC 7638 지문. 키가 없으면 `school` 프로필에서는 시작하지 않고, 로컬·테스트에서는 임시 키를 만들고 경고를 남긴다.
- Q: 관리자·부스 초기 데이터는? → A: 시작할 때 환경 변수 `ADMIN_EMAIL`·`ADMIN_PASSWORD`, `BOOTH_CLIENT_ID`·`BOOTH_CLIENT_SECRET`(trace-secrets)로 없으면 만든다. 이미 있으면 건드리지 않는다(비밀번호를 덮어쓰지 않음). 값이 없으면 건너뛰고 경고만 남긴다.
- Q: 페어링 코드 테이블에 rentalId가 없다(V1)? → A: AGENT JWT에 rentalId 클레임을 넣기로 했으므로(decisions.md 11/2) `V2__pairing_code_rental_id.sql`로 `rental_id` 컬럼을 더한다(더하는 변경).
- Q: QR 링크 수명과 주소는? → A: 30분(설정 `trace.auth.capture-link-ttl`), 주소는 `${WEB_PUBLIC_URL}/capture?t=<토큰>`. 토큰은 32바이트 난수 base64url(43자), DB에는 SHA-256만.
- Q: ID 형식은? → A: 헌법 1.1.0·contracts PR #6대로 DB 기본 키는 bigint로 밖에 내보내지 않고, 밖에 보이는 ID(계정 publicId, rentalId·checkpointId, JWT `sub`·`rentals`·`jti`)는 NanoID 21자다. 페어링 코드에는 publicId가 없어 AGENT JWT의 `sub`는 checkpointId로 둔다. 부스 `sub`·`scope`는 clientId(boothId) 그대로.
- Q: 이미 쓴 페어링 코드는? → A: 계약대로 410 PAIRING_CODE_EXPIRED("만료·이미 사용됨"). 맞는 코드가 없으면 400 PAIRING_CODE_INVALID.

## 사용자 시나리오와 테스트 *(필수)*

### 사용자 이야기 1 - 관리자·고객이 로그인하고 토큰을 다시 받는다 (P1)

관리자(초기 데이터)와 인증을 마친 고객이 이메일·비밀번호로 로그인해 15분 액세스 JWT와 7일 리프레시 쿠키를 받는다. 액세스가 만료되면 쿠키로 다시 받는다.

**독립 테스트**: 초기 관리자로 로그인 → `/auth/me` 200 → 만료된 토큰으로 401 → `/auth/refresh`로 새 토큰 → 로그아웃 뒤 refresh 401.

**수용 시나리오**:

1. **Given** 초기 데이터 관리자, **When** 맞는 이메일·비밀번호로 로그인하면, **Then** 200, `role: ADMIN`, `expiresIn: 900`, `trace_refresh` 쿠키(HttpOnly·Secure·SameSite=Strict·Path=/api/v1/auth·Max-Age=604800)를 받는다.
2. **Given** 틀린 비밀번호 또는 없는 이메일, **When** 로그인하면, **Then** 401 INVALID_CREDENTIALS(둘을 구분하지 않음).
3. **Given** PENDING 고객, **When** 맞는 비밀번호로 로그인하면, **Then** 403 EMAIL_NOT_VERIFIED.
4. **Given** 만료된 액세스 토큰, **When** 보호된 경로를 부르면, **Then** 401이고, **When** 리프레시 쿠키로 `/auth/refresh`를 부르면, **Then** 새 액세스 토큰과 교체된 쿠키를 받는다.
5. **Given** 한 번 쓴(교체된) 리프레시 토큰이나 로그아웃한 토큰, **When** `/auth/refresh`를 부르면, **Then** 401 REFRESH_INVALID.
6. **Given** 렌탈이 연결된 고객, **When** 로그인하거나 재발급하면, **Then** 액세스 JWT의 `rentals` 클레임에 연결된 렌탈 ID가 모두 들어 있다.
7. **Given** 로그인한 사용자, **When** `GET /auth/me`, **Then** 계정 publicId·이메일·이름·역할·상태·`rentalIds`를 받는다(ADMIN은 빈 배열).

### 사용자 이야기 2 - 고객이 QR을 찍어 그 시점만 쓰는 촬영 JWT를 받는다 (P1)

관리자가 수령 시점의 1회용 QR 링크를 발급하고, 로그인한 고객이 QR 토큰을 내면 그 시점 범위의 30분 촬영 JWT를 받고 렌탈이 자기 계정에 연결된다.

**독립 테스트**: 관리자 토큰으로 링크 발급 → 고객 토큰으로 교환 → 촬영 JWT 클레임 확인, 다른 고객이 같은 렌탈의 새 링크로 교환하면 409.

**수용 시나리오**:

1. **Given** ADMIN, **When** `POST /auth/capture-links {rentalId, checkpointId}`, **Then** 201 `{url, expiresAt}`이고 DB에는 토큰의 SHA-256만 남는다.
2. **Given** 유효한 QR 토큰과 로그인한 고객, **When** 교환하면, **Then** 200, 촬영 JWT(role CUSTOMER, scope=checkpointId, rentalId 클레임, 30분)를 받고 렌탈이 계정에 연결된다.
3. **Given** 이미 쓴 토큰 또는 만료된 토큰, **When** 교환하면, **Then** 410 CAPTURE_LINK_INVALID.
4. **Given** 다른 계정에 연결된 렌탈의 링크, **When** 교환하면, **Then** 409 RENTAL_LINKED_TO_OTHER.
5. **Given** 촬영 JWT의 scope, **When** 다른 시점을 요청하는 서비스가 토큰을 읽으면, **Then** scope가 그 시점 하나뿐이라 403(OUT_OF_SCOPE)으로 막을 수 있다. auth-server는 촬영 JWT로 `/auth/me`·로그아웃·발급 경로를 부르면 403을 준다.

### 사용자 이야기 3 - 부스와 에이전트가 자기 자격을 JWT로 바꾼다 (P1)

부스는 client_id·secret으로 1시간 BOOTH JWT를, 진단 에이전트는 화면의 6자리 페어링 코드로 10분 AGENT JWT를 받는다.

**독립 테스트**: 초기 부스 자격으로 토큰 → 클레임 확인. 관리자가 페어링 코드 발급 → 교환 → 재사용 410, 5분 뒤 410.

**수용 시나리오**:

1. **Given** 초기 데이터 부스 자격, **When** `POST /auth/booth/token`, **Then** 200, BOOTH JWT(scope=boothId, 3600초), 틀리거나 비활성이면 401 CLIENT_CREDENTIALS_INVALID.
2. **Given** ADMIN, **When** `POST /auth/pairing-codes {rentalId, checkpointId}`, **Then** 201 `{code(6자리), expiresAt(5분 뒤)}`이고 DB에는 코드의 SHA-256만 남는다.
3. **Given** 발급된 코드, **When** 5분 안에 교환하면, **Then** 200, AGENT JWT(scope=checkpointId, rentalId 클레임, 600초).
4. **Given** 5분이 지난 코드나 이미 쓴 코드, **When** 교환하면, **Then** 410 PAIRING_CODE_EXPIRED. 맞는 코드가 없으면 400 PAIRING_CODE_INVALID.

### 사용자 이야기 4 - gateway와 서버가 JWKS로 토큰을 검증한다 (P1)

**수용 시나리오**:

1. **Given** auth-server, **When** `GET /.well-known/jwks.json`(인증 없음), **Then** `{keys:[{kty:RSA, kid, use:sig, alg:RS256, n, e}]}`를 받고, 발급한 모든 JWT 헤더의 `kid`가 이 키를 가리킨다.
2. **Given** JWKS 공개키, **When** 발급된 JWT를 검증하면, **Then** 서명이 맞고 `iss=trace`, `exp`, `iat`, `jti`가 있다.

### Edge Cases

- 같은 코드 값을 가진 유효한 페어링 코드가 동시에 둘이면 교환할 시점을 고를 수 없다 → 발급 때 유효한 같은 해시가 있으면 다시 뽑는다(최대 5번).
- 같은 QR·페어링 코드를 동시에 두 번 교환 → `used_at IS NULL` 조건부 갱신으로 한 번만 성공, 나머지는 410.
- 같은 렌탈을 두 고객이 동시에 연결 → `rental_access.rental_id` UNIQUE 위반을 409로 바꾼다.
- 탈퇴(WITHDRAWN) 계정의 리프레시 → 401 REFRESH_INVALID.
- 쿠키 없는 `/auth/refresh` → 401 REFRESH_INVALID.
- 형식이 틀린 본문(publicId가 NanoID 21자 아님, 코드가 6자리 숫자 아님) → 400 VALIDATION_FAILED.
- auth-server는 rentalId·checkpointId가 rental-server에 있는지 묻지 않는다(서비스 경계, ADMIN만 발급).

## 요구사항 *(필수)*

### 기능 요구사항

- **FR-001**: 시스템은 이메일(소문자로 비교)·비밀번호(BCrypt)로 ADMIN·CUSTOMER를 로그인시키고 RS256 액세스 JWT(900초)와 리프레시 쿠키(604800초)를 준다. (FR-AUTH-01)
- **FR-002**: 액세스 JWT 클레임은 `iss=trace`, `sub`(계정 publicId), `role`, `iat`, `exp`, `jti`(NanoID)이고 CUSTOMER는 `rentals`(연결된 렌탈 ID 목록)를 더한다.
- **FR-003**: `/auth/refresh`는 리프레시 쿠키를 한 번만 받아들이고 새 쿠키로 교체한다. 계정이 ACTIVE가 아니면 401.
- **FR-004**: `/auth/logout`은 쿠키의 리프레시를 지우고 쿠키를 비운다(Max-Age=0).
- **FR-005**: `GET /auth/me`는 ADMIN·CUSTOMER 일반 토큰에만 연다. 촬영 JWT(scope 있음)와 BOOTH·AGENT는 403.
- **FR-006**: `POST /auth/booth/token`은 BCrypt로 client secret을 확인하고 BOOTH JWT(`sub`·`scope`=clientId, 3600초)를 준다. (FR-AUTH-02)
- **FR-007**: `POST /auth/pairing-codes`(ADMIN)는 6자리 코드를 SecureRandom으로 뽑아 SHA-256과 rentalId·checkpointId·만료(300초)를 저장하고 원문을 한 번 돌려준다. (FR-AUTH-02)
- **FR-008**: `POST /auth/pairing-codes/exchange`(PUBLIC)는 코드를 한 번만 AGENT JWT(`sub`=checkpointId, `scope`=checkpointId, `rentalId`, 600초)로 바꾼다.
- **FR-009**: `POST /auth/capture-links`(ADMIN)는 1회용 토큰을 만들어 SHA-256만 저장하고 `url`·`expiresAt`(1800초 뒤)을 준다. (FR-RNT-04)
- **FR-010**: `POST /auth/capture-links/exchange`(CUSTOMER 일반 토큰)는 토큰을 한 번만 촬영 JWT(`sub`=계정 publicId, role CUSTOMER, `scope`=checkpointId, `rentalId`, 1800초)로 바꾸고 `auth.rental_access`에 렌탈을 연결한다. 다른 계정에 연결돼 있으면 409. (FR-AUTH-02, FR-USR-02)
- **FR-011**: `GET /.well-known/jwks.json`은 인증 없이 서명 공개키를 준다. (FR-AUTH-03 전제)
- **FR-012**: 시작할 때 환경 변수로 관리자 계정과 부스 자격을 없으면 만든다.
- **FR-013**: 모든 오류는 `application/problem+json`, `code`는 codes.yaml `error_code`.
- **FR-014**: 비밀번호·토큰·코드 원문은 로그와 DB에 남기지 않는다(헌법 V).

### 핵심 엔티티

- **Account**(auth.account): 관리자·고객 계정. AU1은 읽기만(관리자 초기 데이터는 만든다).
- **RentalAccess**(auth.rental_access): 고객 계정 ↔ 렌탈 연결, 렌탈당 하나.
- **ClientCredential**(auth.client_credential): 부스 자격.
- **CaptureLink**(auth.capture_link): QR 1회용 토큰의 해시·시점·렌탈·만료·사용.
- **PairingCode**(auth.pairing_code): 페어링 코드의 해시·시점·렌탈(V2)·만료·사용.
- **RefreshToken**(Redis): jti(SHA-256) → 계정 publicId, 7일.

## 성공 기준 *(필수)*

- **SC-001**: 위 수용 시나리오 전부가 자동 테스트로 있고 `./mvnw verify`가 통과한다(JaCoCo 줄 40% 이상).
- **SC-002**: 응답 본문·상태 코드·오류 `code`가 contracts `openapi/auth-server.yaml`과 같다.
- **SC-003**: DB의 capture_link·pairing_code에는 64자 해시만 있고 원문이 없다(테스트로 확인).
- **SC-004**: 발급한 모든 JWT가 JWKS 공개키로 검증된다.

## Assumptions

- 요청 제한(로그인·페어링 교환 IP당 분당 10회)은 gateway(GW1)가 맡는다.
- 서비스로 넘기는 `X-User-Id`·`X-Role`·`X-Scope` 헤더는 gateway(GW1)가 만든다. auth-server는 자기 보호 경로를 직접 JWT로 검증한다.
- 고객 가입·인증(AU2) 전에는 시험용 고객을 테스트 데이터로 만든다.
- AGENT 토큰의 기기 시리얼 클레임(DI1 시리얼 대조용)은 DI1에서 계약과 함께 정한다(이 기능 범위 밖).
