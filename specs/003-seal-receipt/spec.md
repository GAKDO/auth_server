# AU3 봉인 영수증 메일

백로그: AU3 · 요구사항: FR-INT-03 · 계약: contracts `events/trace.record.sealed.schema.json`(소비자 auth-server, 큐 `trace.auth.receipts`, 변경 없음)

## 수용 기준

- report-server가 `trace.record.sealed`를 내면 auth-server가 받아 `auth.seal_receipt`에 시점마다 한 줄 남긴다(checkpoint_id UNIQUE, 같은 이벤트가 두 번 와도 한 줄).
- 렌탈이 고객 계정에 연결돼 있으면(ACTIVE, 이메일 있음) 바로 영수증 메일을 보내고 sent_at을 채운다.
- 연결 전에 봉인된 기록(보통 출고)은 남겨 두었다가, 수령 QR 교환으로 렌탈이 연결될 때 보낸다.
- 같은 시점은 한 번만 보낸다. 보낸 표시는 같은 트랜잭션에서, 메일은 커밋 뒤에 보낸다. 발송이 실패하면 다시 보내지 않고 로그만 남긴다.
- 메일에는 시점 종류(출고·수령·반납), 한국 시간 봉인 시각, 기록 지문(payloadHash, 검증 페이지와 같은 값), 내 렌탈 주소가 들어간다. 로그에는 받는 주소를 남기지 않는다.
- 형식이 깨진 이벤트는 재시도하지 않고 `trace.auth.receipts.dlq`로 보낸다.

## 구현

- `receipt/domain`: SealReceipt(V1 테이블 그대로, 새 마이그레이션 없음), SealReceiptRepository(미발송 조회는 행 잠금)
- `receipt/application`: ReceiptService(record·onRentalLinked), ReceiptMailer
- `receipt/infra`: ReceiptAmqpConfig(큐·DLQ, __TypeId__를 무시하는 리스너 변환기), RecordSealedListener, SmtpReceiptMailer(AU2와 같은 SMTP 설정)
- CaptureLinkService: 렌탈을 처음 연결할 때 ReceiptService.onRentalLinked를 부른다.
- RabbitMQ 헬스는 끈다(영수증 때문에 로그인 서버가 재시작되지 않게).

## 테스트

ReceiptIntegrationTest(실DB: 연결 전 보류 → 연결 시 1회 → 수령 봉인 즉시 1회 → 다시 연결해도 0), RecordSealedListenerTest(contracts 예시 읽기·깨진 이벤트 DLQ), SmtpReceiptMailerTest(본문·SMTP 없음).
