# 데이터 모델: AU1

ID: 기본 키 `id`는 bigint IDENTITY(밖에 안 냄), 계정만 `public_id`(NanoID 21자), 다른 서버의 렌탈·시점은 publicId 값(varchar(21))으로만 든다(헌법 1.1.0).

원본: GAKDO/docs `design/ddl.md` auth 절, `db/V1__init.sql`. Flyway `V1__auth_init.sql`은 그 절을 그대로 옮기고, `V2__pairing_code_rental_id.sql`만 더한다.

## PostgreSQL `auth`

| 테이블 | AU1에서 | 주요 컬럼 | 규칙 |
| --- | --- | --- | --- |
| account | 읽기, 관리자 초기 데이터 쓰기 | id, email(UNIQUE, 소문자), password_hash(BCrypt), name, role(ADMIN·CUSTOMER), status(PENDING·ACTIVE·WITHDRAWN) | 로그인은 ACTIVE만, PENDING은 403 |
| rental_access | 쓰기(QR 교환) | account_id, rental_id(UNIQUE), linked_at | 렌탈당 계정 하나 → 위반은 409 |
| client_credential | 읽기, 초기 데이터 쓰기 | client_id(UNIQUE), secret_hash(BCrypt), kind(BOOTH), active | active=false면 401 |
| capture_link | 쓰기 | checkpoint_id, rental_id, token_hash(char 64, UNIQUE), expires_at, used_at | 1회용(조건부 갱신), 30분 |
| pairing_code | 쓰기 | checkpoint_id, **rental_id(V2)**, code_hash(char 64), expires_at, used_at | 1회용, 5분, 유효한 같은 해시 없음 |

### V2

```sql
ALTER TABLE auth.pairing_code ADD COLUMN rental_id varchar(21);  -- 렌탈 publicId
```

NULL 허용으로 더한다(헌법 "컬럼 추가 먼저"). 새 코드는 항상 채우고, 교환 때 NULL이면 400으로 본다(V2 전 행은 없다).

## Redis

| 키 | 값 | TTL |
| --- | --- | --- |
| `trace:auth:refresh:{sha256(토큰)}` | 계정 publicId | 7일 |
| `trace:auth:refresh:account:{계정 publicId}` | jti 집합 | 7일(갱신 때 연장) |

## 상태 변화

- capture_link·pairing_code: `used_at IS NULL AND expires_at > now` → 교환 → `used_at = now`. 만료·사용된 행은 410.
- 리프레시: 발급 → (refresh) 지우고 새로 발급 / (logout) 지움 / (AU2 재설정) 계정 집합째 지움.
