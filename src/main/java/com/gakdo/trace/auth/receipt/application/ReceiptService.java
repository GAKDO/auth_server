package com.gakdo.trace.auth.receipt.application;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import com.gakdo.trace.auth.account.domain.Account;
import com.gakdo.trace.auth.account.domain.AccountRepository;
import com.gakdo.trace.auth.account.domain.AccountStatus;
import com.gakdo.trace.auth.account.domain.RentalAccess;
import com.gakdo.trace.auth.account.domain.RentalAccessRepository;
import com.gakdo.trace.auth.receipt.domain.SealReceipt;
import com.gakdo.trace.auth.receipt.domain.SealReceiptRepository;

/**
 * 봉인 영수증(FR-INT-03, AU3). 봉인 이벤트를 받으면 영수증을 남기고, 렌탈이 고객에게 연결돼 있으면 바로 보낸다.
 * 연결 전 봉인(보통 출고)은 남겨 두었다가 수령 QR로 연결될 때 보낸다. 같은 시점은 한 번만 보낸다(checkpoint_id UNIQUE, sent_at).
 * 보낸 표시는 DB에, 메일은 커밋 뒤에 보낸다. 발송이 실패하면 다시 보내지 않고 로그로 남긴다(같은 지문을 두 번 보내지 않는 쪽을 택함).
 */
@Service
public class ReceiptService {

    private static final Logger log = LoggerFactory.getLogger(ReceiptService.class);

    private final SealReceiptRepository receipts;
    private final RentalAccessRepository rentalAccesses;
    private final AccountRepository accounts;
    private final ReceiptMailer mailer;
    private final Clock clock;

    public ReceiptService(SealReceiptRepository receipts, RentalAccessRepository rentalAccesses,
                          AccountRepository accounts, ReceiptMailer mailer, Clock clock) {
        this.receipts = receipts;
        this.rentalAccesses = rentalAccesses;
        this.accounts = accounts;
        this.mailer = mailer;
        this.clock = clock;
    }

    /** @return 새로 남겼으면 true, 이미 받은 시점이면 false */
    @Transactional
    public boolean record(SealedRecord sealed) {
        if (receipts.existsByCheckpointId(sealed.checkpointId())) {
            return false;
        }
        Instant now = clock.instant();
        try {
            receipts.saveAndFlush(new SealReceipt(sealed.rentalId(), sealed.checkpointId(), sealed.checkpointType(),
                    sealed.payloadHash(), sealed.sealedAt(), now));
        } catch (DataIntegrityViolationException e) {
            // 같은 이벤트가 동시에 두 번 왔다(checkpoint_id UNIQUE). 먼저 들어간 쪽이 보낸다
            return false;
        }
        rentalAccesses.findByRentalId(sealed.rentalId())
                .ifPresent(access -> sendPending(access, now));
        return true;
    }

    /** 수령 QR로 렌탈이 고객에게 연결된 직후(같은 트랜잭션) 부른다. 남아 있던 영수증을 보낸다. */
    @Transactional
    public int onRentalLinked(RentalAccess access) {
        return sendPending(access, clock.instant());
    }

    private int sendPending(RentalAccess access, Instant now) {
        Optional<Account> customer = accounts.findById(access.getAccountId())
                .filter(a -> a.getStatus() == AccountStatus.ACTIVE && a.getEmail() != null);
        if (customer.isEmpty()) {
            return 0;
        }
        List<SealReceipt> pending = receipts.findByRentalIdAndSentAtIsNullOrderBySealedAtAsc(access.getRentalId());
        String to = customer.get().getEmail();
        String name = customer.get().getName();
        for (SealReceipt receipt : pending) {
            receipt.markSent(now);
            ReceiptMailer.Receipt mail = new ReceiptMailer.Receipt(receipt.getRentalId(), receipt.getCheckpointType(),
                    receipt.getPayloadHash(), receipt.getSealedAt());
            afterCommit(() -> mailer.send(to, name, mail));
        }
        if (!pending.isEmpty()) {
            log.info("봉인 영수증 {}건을 보냅니다 rentalId={}", pending.size(), access.getRentalId());
        }
        return pending.size();
    }

    private static void afterCommit(Runnable action) {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    action.run();
                }
            });
        } else {
            action.run();
        }
    }
}
