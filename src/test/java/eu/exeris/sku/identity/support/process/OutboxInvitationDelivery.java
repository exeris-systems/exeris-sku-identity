package eu.exeris.sku.identity.support.process;

import eu.exeris.sku.identity.auth.InvitationDelivery;
import eu.exeris.sku.identity.auth.InvitationNotice;

/** Writes each token to the outbox file for the test to read, standing in for a durable mail outbox. */
public final class OutboxInvitationDelivery implements InvitationDelivery {

    static final String FILE = "outbox";

    @Override
    public void deliver(InvitationNotice notice) {
        RlsProbe.run("issue");
        HostFiles.append(FILE, notice.recipientEmail() + "|" + notice.rawToken());
    }
}
