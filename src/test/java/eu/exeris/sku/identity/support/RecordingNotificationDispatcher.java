package eu.exeris.sku.identity.support;

import eu.exeris.caps.credentialstore.spi.NotificationDispatcher;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

/** Keeps the tokens it is asked to deliver, so a test can use them. */
public final class RecordingNotificationDispatcher implements NotificationDispatcher {

    /** One delivery request. */
    public record Sent(UUID subjectId, String recipient, String token) {
    }

    private final List<Sent> verifications = new CopyOnWriteArrayList<>();
    private final List<Sent> resets = new CopyOnWriteArrayList<>();

    @Override
    public void sendVerificationToken(UUID subjectId, String recipientEmail, String rawToken) {
        verifications.add(new Sent(subjectId, recipientEmail, rawToken));
    }

    @Override
    public void sendPasswordResetToken(UUID subjectId, String recipientEmail, String rawToken) {
        resets.add(new Sent(subjectId, recipientEmail, rawToken));
    }

    /** Verification tokens requested so far. */
    public List<Sent> verifications() {
        return verifications;
    }

    /** Password-reset tokens requested so far. */
    public List<Sent> resets() {
        return resets;
    }
}
