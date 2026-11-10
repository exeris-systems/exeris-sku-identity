package eu.exeris.sku.identity.support;

import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import eu.exeris.sku.identity.auth.InvitationDelivery;
import eu.exeris.sku.identity.auth.InvitationNotice;
import eu.exeris.sku.identity.auth.JoinsServiceTransactions;

/**
 * A host part loadable by class name that records each delivery in an outbox table of the service's
 * database, through the executor it is handed. The token itself is not stored.
 */
public final class TransactionalOutboxDelivery implements InvitationDelivery, JoinsServiceTransactions {

    /** The table the part writes; the test creates it. */
    public static final String TABLE = "host_outbox";

    private volatile TransactionalExecutor executor;
    private volatile boolean failAfterWrite;

    @Override
    public void joinTransactionsOf(TransactionalExecutor executor) {
        this.executor = executor;
    }

    /** Lets later deliveries succeed again. */
    public void stopFailing() {
        failAfterWrite = false;
    }

    /** Makes every later delivery throw after it has written its row. */
    public void failAfterWrite() {
        failAfterWrite = true;
    }

    @Override
    public void deliver(InvitationNotice notice) {
        TransactionalExecutor joined = executor;
        if (joined == null) {
            throw new IllegalStateException("the executor was never handed over");
        }
        joined.executeManaged(connection -> {
            var statement = connection.prepare("INSERT INTO " + TABLE + " (recipient) VALUES ($1)");
            statement.bindString(0, notice.recipientEmail());
            statement.executeUpdate();
        });
        if (failAfterWrite) {
            throw new IllegalStateException("the mail channel is down");
        }
    }
}
