// 이 파일이 확인하는 것: 요구사항 AU3(봉인 영수증 메일)을 진짜 DB로 확인.
// 출고 때는 아직 고객 계정과 렌탈이 연결되지 않았을 수 있다(고객은 수령 때 QR로 연결).
// 그래서 연결 전 봉인은 보관해 두었다가, 연결되는 순간 한 번에 보낸다. 메일은 가짜로 바꿔 보낸 횟수만 센다.

package com.gakdo.trace.auth.receipt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.time.Instant;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.support.TransactionTemplate;

import com.gakdo.trace.auth.account.domain.Account;
import com.gakdo.trace.auth.account.domain.AccountRepository;
import com.gakdo.trace.auth.account.domain.AccountStatus;
import com.gakdo.trace.auth.account.domain.RentalAccess;
import com.gakdo.trace.auth.account.domain.RentalAccessRepository;
import com.gakdo.trace.auth.common.infra.NanoId;
import com.gakdo.trace.auth.receipt.application.ReceiptMailer;
import com.gakdo.trace.auth.receipt.application.ReceiptService;
import com.gakdo.trace.auth.receipt.infra.RecordSealedListener;
import com.gakdo.trace.auth.support.IntegrationTestBase;

/**
 * AU3(봉인 영수증 메일) 수용 기준을 실제 PostgreSQL(auth.seal_receipt 표)로 확인한다.
 *
 * <p>확인하는 흐름: 출고 검사가 봉인됨(아직 고객 계정과 렌탈이 연결 전) → 메일을 보내지 않고 보관 →
 * 고객이 수령 때 QR로 렌탈을 연결 → 그때 한 번만 보냄(다시 연결해도 또 보내지 않음). 메일 발송은 가짜로 바꿔 횟수만 센다.
 *
 * <p>실행 조건: 진짜 PostgreSQL·Redis가 필요하다(바탕 클래스 IntegrationTestBase).
 * GitHub Actions는 Docker(Testcontainers)로 띄우고, Docker가 없으면 {@code TRACE_IT_LOCAL=1}일 때 로컬 테스트 전용 DB
 * trace_it·Redis DB 15에 붙는다. 둘 다 없으면 이 클래스 전체를 건너뛴다(실패가 아님).
 */
// (도구) @EnabledIf = 조건(진짜 DB를 쓸 수 있는지)이 맞을 때만 이 테스트 클래스를 돌린다
@EnabledIf("com.gakdo.trace.auth.support.IntegrationTestBase#infrastructureAvailable")
class ReceiptIntegrationTest extends IntegrationTestBase {

    // 봉인 이벤트에 넣을 지문(64자 해시) 예시 값
    private static final String HASH = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    // (도구) @Autowired = 스프링이 만들어 둔 진짜 부품을 넣어 준다
    // "봉인됨" 이벤트 리스너(진짜)
    @Autowired
    RecordSealedListener listener;
    // 영수증 서비스(진짜): 렌탈 연결 때 보관한 영수증을 보낸다
    @Autowired
    ReceiptService receipts;
    // 계정 저장소(진짜 DB)
    @Autowired
    AccountRepository accounts;
    // 고객-렌탈 연결 저장소(진짜 DB)
    @Autowired
    RentalAccessRepository rentalAccesses;
    // (도구) TransactionTemplate = 코드 한 덩어리를 DB 거래(트랜잭션) 하나로 묶어 실행하는 도구
    @Autowired
    TransactionTemplate tx;
    // (도구) JdbcTemplate = SQL을 직접 실행해 DB 내용을 확인하는 도구
    @Autowired
    JdbcTemplate jdbc;
    // (도구) @MockitoBean = 진짜 대신 가짜(목)를 스프링에 끼워 넣는다. 메일을 실제로 보내지 않고 보낸 횟수만 세려고
    @MockitoBean
    ReceiptMailer mailer;

    // [상황] 출고 봉인 이벤트가 두 번(중복) 온다 → 고객이 QR로 렌탈을 연결 → 수령 봉인 이벤트 → 연결 처리 한 번 더.
    // [기대] 연결 전에는 보내지 않고 기록만 해 둔다(중복 이벤트는 무시). 연결되면 출고 영수증 1통.
    //        수령 봉인은 바로 1통(총 2통). 연결 처리를 또 해도 더 보내지 않는다.
    // (도구) @Test = JUnit에게 "이 메서드가 테스트 하나"라고 알리는 표시. @DisplayName = 결과 화면에 보일 한글 이름
    @Test
    @DisplayName("고객 연결 전 봉인은 보내지 않고 남겨 두었다가, 수령 때 렌탈이 연결되면 한 번만 보낸다")
    void pendingUntilLinkedThenOnce() {
        // 준비: 지금 시각
        Instant now = Instant.now();
        // 준비: 다른 실행과 겹치지 않게 새 고객 이메일을 만든다
        String email = "renter-" + NanoId.next().toLowerCase() + "@trace.test";
        // 준비: 이름이 홍길동인 사용 가능 고객 계정을 DB에 저장한다
        Account customer = accounts.saveAndFlush(
                Account.customer(NanoId.next(), email, "x", "홍길동", AccountStatus.ACTIVE, now));
        // 준비: 새 렌탈 ID
        String rentalId = NanoId.next();
        // 준비: 새 출고 시점 ID
        String outbound = NanoId.next();

        // (도구) assertThat(값).isTrue() = 값이 true여야 통과하는 AssertJ 검사
        // 실행+확인: 출고 봉인 이벤트를 처리하면 처음이라 true(새로 기록함)여야 한다
        assertThat(listener.handle(sealed(rentalId, outbound, "OUT"))).isTrue();
        // (도구) isFalse() = 값이 false여야 통과
        // 실행+확인: 같은 시점 봉인 이벤트가 또 오면 false(중복이라 무시)여야 한다
        assertThat(listener.handle(sealed(rentalId, outbound, "OUT"))).isFalse();
        // (도구) verify(가짜, never()).메서드(any()...) = 그 메서드가 한 번도 불리지 않았는지 확인. any() = 아무 값이나
        // 확인: 아직 고객과 렌탈이 연결 전이라 메일을 보내지 않았어야 한다
        verify(mailer, never()).send(any(), any(), any());
        // (도구) isNull() = 값이 없어야(null) 통과
        // 확인: DB의 보낸 시각도 비어 있어야 한다 = 보관만 해 둔 상태
        assertThat(sentAt(outbound)).isNull();

        // 실행: 한 거래 안에서 고객-렌탈 연결을 저장하고, 연결 처리를 불러 보낸 영수증 수를 받는다(QR 연결 순간)
        Integer sent = tx.execute(status -> receipts.onRentalLinked(
                rentalAccesses.saveAndFlush(new RentalAccess(customer.getId(), rentalId, now))));
        // (도구) isEqualTo(값) = 그 값과 같아야 통과
        // 확인: 보관해 둔 출고 영수증 1통을 보냈어야 한다
        assertThat(sent).isEqualTo(1);
        // (도구) times(1) = 정확히 1번. eq(값) = 그 값과 같을 때만 센다
        // 확인: 그 고객 이메일·이름으로 메일이 1번 나갔어야 한다
        verify(mailer, times(1)).send(eq(email), eq("홍길동"), any());
        // (도구) isNotNull() = 값이 있어야 통과
        // 확인: DB에 보낸 시각이 기록돼야 한다
        assertThat(sentAt(outbound)).isNotNull();

        // 준비: 새 수령 시점 ID
        String received = NanoId.next();
        // 실행+확인: 수령 봉인 이벤트를 처리하면 true여야 한다
        assertThat(listener.handle(sealed(rentalId, received, "RCV"))).isTrue();
        // 확인: 이미 연결된 렌탈이라 바로 보내 총 2번 나갔어야 한다
        verify(mailer, times(2)).send(eq(email), eq("홍길동"), any());
        // 실행: 연결 처리를 한 번 더 부른다(다시 연결한 상황)
        Integer again = tx.execute(status -> receipts.onRentalLinked(
                rentalAccesses.findByRentalId(rentalId).orElseThrow()));
        // (도구) isZero() = 0이어야 통과
        // 확인: 새로 보낸 영수증이 0통이어야 한다
        assertThat(again).isZero();
        // 확인: 전체 메일 수가 여전히 2번이어야 한다 = 같은 영수증을 두 번 보내지 않는다
        verify(mailer, times(2)).send(any(), any(), any());
    }

    // 테스트 도구: 그 시점 영수증의 보낸 시각을 DB에서 읽는다(안 보냈으면 null)
    private Instant sentAt(String checkpointId) {
        // seal_receipt 표에서 시점 ID로 보낸 시각을 읽어 돌려준다
        return jdbc.queryForObject("SELECT sent_at FROM auth.seal_receipt WHERE checkpoint_id = ?", Instant.class,
                checkpointId);
    }

    // 테스트 도구: 렌탈·시점·종류를 넣은 "봉인됨" 이벤트 JSON 글자를 만든다
    private static String sealed(String rentalId, String checkpointId, String type) {
        // JSON 틀에 새 이벤트 ID·렌탈·시점·종류·지문을 채워 돌려준다
        return """
                {"schemaVersion":"1.0","eventId":"%s","occurredAt":"2026-11-09T14:10:31+09:00",
                 "rentalId":"%s","checkpointId":"%s","seq":1,"checkpointType":"%s","grade":"B",
                 "payloadHash":"%s","prevHash":null,"signedAt":"2026-11-09T14:10:31+09:00"}
                """.formatted(NanoId.next(), rentalId, checkpointId, type, HASH);
    }
}
