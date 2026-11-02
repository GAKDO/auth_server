-- AGENT JWT에 rentalId 클레임을 넣으려고 페어링 코드에 렌탈을 함께 둔다(contracts PR #4, docs decisions.md 11/2).
-- 헌법 "컬럼 추가 먼저"에 따라 NULL 허용으로 더한다. 새 코드는 항상 채운다.
ALTER TABLE auth.pairing_code ADD COLUMN rental_id varchar(21);  -- 렌탈 publicId(NanoID). 다른 서버의 행이라 FK 없이 값만 둔다
