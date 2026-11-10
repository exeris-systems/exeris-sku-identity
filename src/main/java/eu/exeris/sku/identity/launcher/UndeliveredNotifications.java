package eu.exeris.sku.identity.launcher;

import eu.exeris.caps.credentialstore.spi.NotificationDispatcher;

import java.util.UUID;

/**
 * Used when no delivery channel is configured. A token it is handed goes nowhere; only the fact that one
 * was requested is logged, never the token or the address.
 */
final class UndeliveredNotifications implements NotificationDispatcher {

    private static final System.Logger LOG = System.getLogger(UndeliveredNotifications.class.getName());

    @Override
    public void sendVerificationToken(UUID subjectId, String recipientEmail, String rawToken) {
        LOG.log(System.Logger.Level.WARNING, "A verification token was requested for {0} and not delivered: "
                + "no notification dispatcher is configured", subjectId);
    }

    @Override
    public void sendPasswordResetToken(UUID subjectId, String recipientEmail, String rawToken) {
        LOG.log(System.Logger.Level.WARNING, "A password-reset token was requested for {0} and not delivered: "
                + "no notification dispatcher is configured", subjectId);
    }
}
