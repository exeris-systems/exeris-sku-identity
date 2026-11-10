package eu.exeris.sku.identity.wiring;

import eu.exeris.caps.credentialstore.spi.AuditRecorder;
import eu.exeris.sku.identity.persistence.JoiningTransactionalExecutor;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Records an audit event only after the transaction it was raised in has committed. Inside a joined unit
 * the event is queued and dropped if the unit rolls back, so the trail never names a change that did not
 * happen; outside a unit it is recorded at once.
 */
public final class CommitOrderedAuditRecorder implements AuditRecorder {

    private final AuditRecorder delegate;

    /**
     * @param delegate where the events are recorded
     */
    public CommitOrderedAuditRecorder(AuditRecorder delegate) {
        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
    }

    @Override
    public void recordEvent(String action, UUID subjectId, Map<String, Object> details, Instant occurredAt) {
        JoiningTransactionalExecutor.afterCommit(() -> delegate.recordEvent(action, subjectId, details, occurredAt));
    }
}
