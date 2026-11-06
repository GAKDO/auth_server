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

/** AU3 수용 기준을 실제 PostgreSQL(auth.seal_receipt)로: 연결 전 봉인은 남겨 두고, 연결되면 한 번만 보낸다. */
@EnabledIf("com.gakdo.trace.auth.support.IntegrationTestBase#infrastructureAvailable")
class ReceiptIntegrationTest extends IntegrationTestBase {

    private static final String HASH = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    @Autowired
    RecordSealedListener listener;
    @Autowired
    ReceiptService receipts;
    @Autowired
    AccountRepository accounts;
    @Autowired
    RentalAccessRepository rentalAccesses;
    @Autowired
    TransactionTemplate tx;
    @Autowired
    JdbcTemplate jdbc;
    @MockitoBean
    ReceiptMailer mailer;

    @Test
    @DisplayName("고객 연결 전 봉인은 보내지 않고 남겨 두었다가, 수령 때 렌탈이 연결되면 한 번만 보낸다")
    void pendingUntilLinkedThenOnce() {
        Instant now = Instant.now();
        String email = "renter-" + NanoId.next().toLowerCase() + "@trace.test";
        Account customer = accounts.saveAndFlush(
                Account.customer(NanoId.next(), email, "x", "홍길동", AccountStatus.ACTIVE, now));
        String rentalId = NanoId.next();
        String outbound = NanoId.next();

        assertThat(listener.handle(sealed(rentalId, outbound, "OUT"))).isTrue();
        assertThat(listener.handle(sealed(rentalId, outbound, "OUT"))).isFalse();
        verify(mailer, never()).send(any(), any(), any());
        assertThat(sentAt(outbound)).isNull();

        Integer sent = tx.execute(status -> receipts.onRentalLinked(
                rentalAccesses.saveAndFlush(new RentalAccess(customer.getId(), rentalId, now))));
        assertThat(sent).isEqualTo(1);
        verify(mailer, times(1)).send(eq(email), eq("홍길동"), any());
        assertThat(sentAt(outbound)).isNotNull();

        String received = NanoId.next();
        assertThat(listener.handle(sealed(rentalId, received, "RCV"))).isTrue();
        verify(mailer, times(2)).send(eq(email), eq("홍길동"), any());
        Integer again = tx.execute(status -> receipts.onRentalLinked(
                rentalAccesses.findByRentalId(rentalId).orElseThrow()));
        assertThat(again).isZero();
        verify(mailer, times(2)).send(any(), any(), any());
    }

    private Instant sentAt(String checkpointId) {
        return jdbc.queryForObject("SELECT sent_at FROM auth.seal_receipt WHERE checkpoint_id = ?", Instant.class,
                checkpointId);
    }

    private static String sealed(String rentalId, String checkpointId, String type) {
        return """
                {"schemaVersion":"1.0","eventId":"%s","occurredAt":"2026-11-09T14:10:31+09:00",
                 "rentalId":"%s","checkpointId":"%s","seq":1,"checkpointType":"%s","grade":"B",
                 "payloadHash":"%s","prevHash":null,"signedAt":"2026-11-09T14:10:31+09:00"}
                """.formatted(NanoId.next(), rentalId, checkpointId, type, HASH);
    }
}
