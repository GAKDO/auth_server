-- 사용자가 비밀번호를 직접 정했는지(11/12 팀 결정: 비밀번호를 정한 적 없는 소셜 가입자는 비밀번호 없이 탈퇴).
-- 비밀번호 가입·재설정은 true, 소셜 가입과 인증 전 계정의 소셜 전환(난수 비밀번호)은 false.
ALTER TABLE auth.account ADD COLUMN password_set boolean NOT NULL DEFAULT true;

-- 이미 있는 계정 채우기: 소셜 가입과 인증 전 계정의 소셜 전환은 소셜 연결 시각에 이메일 인증도 끝나므로 두 시각이 같다.
-- 비밀번호로 가입해 메일 인증을 먼저 끝낸 계정은 연결 시각이 더 늦어 true로 남는다.
-- (소셜 가입 뒤 이 마이그레이션 전에 비밀번호를 재설정한 계정은 false로 남지만, 10분 안 로그인 조건은 그대로 걸린다.)
UPDATE auth.account a
   SET password_set = false
 WHERE a.status <> 'WITHDRAWN'
   AND EXISTS (SELECT 1 FROM auth.social_identity s
                WHERE s.account_id = a.id AND s.linked_at = a.email_verified_at);
