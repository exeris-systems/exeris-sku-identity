package eu.exeris.sku.identity.support;

import eu.exeris.sku.identity.auth.InvitationDelivery;
import eu.exeris.sku.identity.auth.InvitationNotice;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

/** Keeps the invitations it is asked to deliver, so a test can read the token the invitee would receive. */
public final class RecordingInvitationDelivery implements InvitationDelivery {

    private final List<InvitationNotice> notices = new CopyOnWriteArrayList<>();
    private final AtomicBoolean failNext = new AtomicBoolean();

    @Override
    public void deliver(InvitationNotice notice) {
        if (failNext.getAndSet(false)) {
            throw new IllegalStateException("the mail channel is down");
        }
        notices.add(notice);
    }

    /** Makes the next delivery throw. */
    public void failNext() {
        failNext.set(true);
    }

    /** Everything delivered so far. */
    public List<InvitationNotice> notices() {
        return notices;
    }

    /** The token delivered to the address most recently. */
    public String tokenFor(String email) {
        for (int i = notices.size() - 1; i >= 0; i--) {
            if (notices.get(i).recipientEmail().equals(email)) {
                return notices.get(i).rawToken();
            }
        }
        throw new AssertionError("no invitation was delivered to " + email);
    }

    @Override
    public String toString() {
        return "RecordingInvitationDelivery[" + notices.size() + " delivered]";
    }
}
