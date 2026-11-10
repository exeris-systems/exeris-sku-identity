package eu.exeris.sku.identity.support.process;

import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import eu.exeris.sku.identity.auth.InvitationDelivery;
import eu.exeris.sku.identity.auth.InvitationNotice;
import eu.exeris.sku.identity.auth.JoinsServiceTransactions;

/** Writes each token to the outbox file for the test to read, standing in for a durable mail outbox. */
public final class OutboxInvitationDelivery implements InvitationDelivery, JoinsServiceTransactions {

    static final String FILE = "outbox";

    @Override
    public void joinTransactionsOf(TransactionalExecutor executor) {
        RlsProbe.join(executor);
    }

    @Override
    public void deliver(InvitationNotice notice) {
        RlsProbe.run("issue");
        HostFiles.append(FILE, notice.recipientEmail() + "|" + notice.rawToken());
    }
}
