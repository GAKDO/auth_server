# 변경 기록

이 레포의 버전별 변경을 적는다. 형식은 [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/)를 따른다.
기능 PR은 `## [Unreleased]` 아래에 한 줄을 더하고, 릴리스 PR에서 `## [x.y.z] - 날짜`로 바꾼다(CONTRIBUTING.md 3번).
main에 버전이 적힌 CHANGELOG가 올라가면 release.yml이 태그와 GitHub Release를 만든다.

## [Unreleased]

### 변경
- 페어링 코드 발급 요청에 `deviceSerial`(필수, 렌탈 기기 등록 시리얼)을 받아 저장(Flyway V3)하고, AGENT JWT 클레임과 교환 응답에 `deviceSerial`을 넣음 (contracts auth-server 0.2.0, 11/2 결정)

## [0.1.0] - 2026-11-02

**목표: 첫 클러스터 배포와 관리자 로그인**
관리자 로그인과 JWT 발급, 부스 자격 교환, JWKS 공개키를 클러스터에서 쓸 수 있게 한다.

### 추가
- 블로그(AIGJ-01-002-blog/devlog) CI/CD를 옮겨 초기 구성
- AU1 로그인·JWT·자격 교환, 초기 관리자·부스 자격 생성 (FR-AUTH-01·02) (#1)
