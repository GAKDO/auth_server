-- AGENT JWT에 deviceSerial 클레임을 넣으려고 페어링 코드에 렌탈 기기의 등록 시리얼을 함께 둔다(contracts auth-server 0.2.0, 11/2 결정).
-- 헌법 "컬럼 추가 먼저"에 따라 NULL 허용으로 더한다. 새 코드는 항상 채운다.
ALTER TABLE auth.pairing_code ADD COLUMN device_serial varchar(64);  -- rental-server 기기 serial. 다른 서버의 행이라 FK 없이 값만 둔다
