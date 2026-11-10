package eu.exeris.sku.identity.http;

import eu.exeris.caps.credentialstore.api.exception.CredentialAlreadyExistsException;
import eu.exeris.caps.invitations.api.exception.InvalidInvitationException;
import eu.exeris.caps.invitations.api.exception.InvitationAccessDeniedException;
import eu.exeris.caps.invitations.api.model.Invitation;
import eu.exeris.caps.invitations.api.model.IssuedInvitation;
import eu.exeris.kernel.spi.context.KernelProviders;
import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.security.PrincipalContext;
import eu.exeris.sku.identity.IdentityServices;
import eu.exeris.sku.identity.auth.InvitationDelivery;
import eu.exeris.sku.identity.auth.InvitationNotice;
import eu.exeris.sku.identity.auth.RoleScopes;
import eu.exeris.sku.identity.auth.TenantScope;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Inviting people into the caller's tenant, and accepting an invitation.
 *
 * <p>Issuing takes the actor and the tenant from the caller's token alone, and hands the single-use token to
 * the invitation delivery: the response to the inviter never carries it. Accepting is public, because the
 * invitee has no account yet; it takes the tenant from the invitation it consumes, which is only found when
 * the token, the tenant and the address in the request all match one pending invitation.
 */
final class InvitationHandlers {

    /** The lifetime of an invitation when the request names none. */
    static final Duration DEFAULT_TTL = Duration.ofDays(7);

    private static final String SUBJECT_NAMESPACE = "eu.exeris.sku.identity/invitation-subject/";
    private static final System.Logger LOG = System.getLogger(InvitationHandlers.class.getName());
    private static final Pattern ROLE = Pattern.compile("[a-z][a-z0-9-]{0,31}");
    private static final int MAX_EMAIL = 254;
    private static final int MAX_TOKEN = 128;

    private final IdentityServices services;
    private final JsonBodies bodies;
    private final Responses responses;

    InvitationHandlers(IdentityServices services, JsonBodies bodies, Responses responses) {
        this.services = services;
        this.bodies = bodies;
        this.responses = responses;
    }

    /**
     * Issues an invitation into the tenant the caller's token names and hands its token to the invitation
     * delivery. The platform role is never grantable, and only an owner may invite another owner.
     *
     * <p>The invitation is stored and delivered in one transaction: if the delivery fails, nothing is
     * stored. With no delivery configured the call is refused before the body is read.
     */
    void issue(HttpExchange exchange) {
        InvitationDelivery delivery = services.invitationDelivery()
                .orElseThrow(Problem.INVITATION_DELIVERY_UNAVAILABLE::raise);
        JsonBodies.Fields body = bodies.read(exchange, Set.of("email", "role", "ttlSeconds"));
        PrincipalContext principal = KernelProviders.principal();
        UUID tenant = principal.tenantId().orElseThrow(Problem.TENANT_REQUIRED::raise);
        String email = body.string("email", MAX_EMAIL);
        String role = body.string("role", 32);
        if (!ROLE.matcher(role).matches() || !RoleScopes.issuable(role)
                || (RoleScopes.OWNER.equals(role) && !principal.hasRole(RoleScopes.OWNER))) {
            throw Problem.FORBIDDEN.raise();
        }
        Duration ttl = body.optionalLong("ttlSeconds", 60, DEFAULT_TTL.toSeconds())
                .map(Duration::ofSeconds).orElse(DEFAULT_TTL);
        Invitation invitation;
        try {
            invitation = services.transactions().inTransaction(() -> {
                IssuedInvitation issued = services.invitations().issue(tenant, principal.principalId(), email, role, ttl);
                try {
                    delivery.deliver(InvitationNotice.of(issued));
                } catch (RuntimeException e) {
                    LOG.log(System.Logger.Level.WARNING, "an invitation could not be delivered: {0}",
                            e.getClass().getName());
                    throw Problem.INVITATION_DELIVERY_FAILED.raise();
                }
                return issued.invitation();
            });
        } catch (InvitationAccessDeniedException e) {
            throw Problem.FORBIDDEN.raise();
        } catch (InvalidInvitationException e) {
            throw Problem.INVALID_REQUEST.raise();
        }
        responses.json(exchange, HttpStatus.CREATED, Responses.object(
                "invitationId", invitation.id().toString(),
                "tenantId", invitation.tenantId().toString(),
                "email", invitation.email(),
                "role", invitation.role(),
                "expiresAt", invitation.expiresAt().toString()));
    }

    /**
     * Creates the account of the invitee and makes it a member of the invitation's tenant, with the
     * invitation's role.
     *
     * <p>The account is created verified, because the token reached only the invitee's mailbox. The
     * invitation is consumed first, in one conditional write that checks the token, tenant, address, expiry
     * and revocation together; the account and the membership follow in the same transaction. The account
     * exists if and only if the invitation is consumed, and a response is sent only after the commit.
     *
     * <p>The account's subject is derived from the invitation, so a repeated attempt after a failure that
     * left a membership behind creates the same subject and adopts that membership instead of adding a
     * second one.
     */
    void accept(HttpExchange exchange) {
        JsonBodies.Fields body = bodies.read(exchange, Set.of("tenantId", "token", "email", "password"));
        UUID tenant = body.uuid("tenantId");
        String token = body.string("token", MAX_TOKEN);
        String email = body.string("email", MAX_EMAIL);
        char[] password = body.password("password");
        try {
            Invitation consumed = TenantScope.call(tenant,
                    () -> services.transactions().inTransaction(() -> acceptInTenant(tenant, token, email, password)));
            responses.json(exchange, HttpStatus.CREATED, Responses.object(
                    "tenantId", consumed.tenantId().toString(),
                    "role", consumed.role()));
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private Invitation acceptInTenant(UUID tenant, String token, String email, char[] password) {
        Invitation consumed;
        try {
            consumed = services.invitations().consume(token, tenant, email);
        } catch (InvalidInvitationException e) {
            throw Problem.INVALID_INVITATION.raise();
        }
        UUID subject = subjectOf(consumed.id());
        try {
            services.credentialProvisioning().provisionVerified(subject, consumed.email(), password.clone());
        } catch (CredentialAlreadyExistsException e) {
            throw Problem.ACCOUNT_EXISTS.raise();
        } catch (IllegalArgumentException e) {
            throw Problem.INVALID_PASSWORD.raise();
        }
        services.memberships().grant(consumed.tenantId(), subject, consumed.role());
        return consumed;
    }

    /** The subject of the account an invitation creates; the same invitation always yields the same one. */
    static UUID subjectOf(UUID invitationId) {
        return UUID.nameUUIDFromBytes((SUBJECT_NAMESPACE + invitationId).getBytes(StandardCharsets.UTF_8));
    }
}
