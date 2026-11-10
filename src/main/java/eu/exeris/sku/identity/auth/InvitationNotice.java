package eu.exeris.sku.identity.auth;

import eu.exeris.caps.invitations.api.model.Invitation;
import eu.exeris.caps.invitations.api.model.IssuedInvitation;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * What an {@link InvitationDelivery} is given for one invitation.
 *
 * <p>The text form names every component except the token.
 *
 * @param invitationId   the invitation
 * @param tenantId       the tenant the invitee is invited into
 * @param recipientEmail the address the token is to be delivered to
 * @param role           the role the invitee will hold
 * @param expiresAt      when the invitation stops being acceptable
 * @param rawToken       the single-use token; it is a secret
 */
public record InvitationNotice(UUID invitationId, UUID tenantId, String recipientEmail, String role,
                               Instant expiresAt, String rawToken) {

    public InvitationNotice {
        Objects.requireNonNull(invitationId, "invitationId must not be null");
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(recipientEmail, "recipientEmail must not be null");
        Objects.requireNonNull(role, "role must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        Objects.requireNonNull(rawToken, "rawToken must not be null");
    }

    /** The notice for a freshly issued invitation. */
    public static InvitationNotice of(IssuedInvitation issued) {
        Invitation invitation = issued.invitation();
        return new InvitationNotice(invitation.id(), invitation.tenantId(), invitation.email(), invitation.role(),
                invitation.expiresAt(), issued.rawToken());
    }

    @Override
    public String toString() {
        return "InvitationNotice[invitationId=" + invitationId + ", tenantId=" + tenantId
                + ", recipientEmail=" + recipientEmail + ", role=" + role + ", expiresAt=" + expiresAt + "]";
    }
}
