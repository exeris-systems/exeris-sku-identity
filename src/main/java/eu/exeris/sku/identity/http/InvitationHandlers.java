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
import eu.exeris.sku.identity.auth.RoleScopes;
import eu.exeris.sku.identity.auth.TenantScope;

import java.time.Duration;
import java.util.Arrays;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Inviting people into the caller's tenant, and accepting an invitation.
 *
 * <p>Issuing takes the actor and the tenant from the caller's token alone. Accepting is public, because the
 * invitee has no account yet; it takes the tenant from the invitation it consumes, which is only found when
 * the token, the tenant and the address in the request all match one pending invitation.
 */
final class InvitationHandlers {

    /** The lifetime of an invitation when the request names none. */
    static final Duration DEFAULT_TTL = Duration.ofDays(7);

    private static final String PLATFORM_ADMIN = "platform-admin";
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
     * Issues an invitation into the tenant the caller's token names. The platform role is never
     * grantable, and only an owner may invite another owner.
     */
    void issue(HttpExchange exchange) {
        JsonBodies.Fields body = bodies.read(exchange, Set.of("email", "role", "ttlSeconds"));
        PrincipalContext principal = KernelProviders.principal();
        UUID tenant = principal.tenantId().orElseThrow(Problem.TENANT_REQUIRED::raise);
        String email = body.string("email", MAX_EMAIL);
        String role = body.string("role", 32);
        if (!ROLE.matcher(role).matches() || PLATFORM_ADMIN.equals(role)
                || (RoleScopes.OWNER.equals(role) && !principal.hasRole(RoleScopes.OWNER))) {
            throw Problem.FORBIDDEN.raise();
        }
        Duration ttl = body.optionalLong("ttlSeconds", 60, DEFAULT_TTL.toSeconds())
                .map(Duration::ofSeconds).orElse(DEFAULT_TTL);
        IssuedInvitation issued;
        try {
            issued = services.invitations().issue(tenant, principal.principalId(), email, role, ttl);
        } catch (InvitationAccessDeniedException e) {
            throw Problem.FORBIDDEN.raise();
        } catch (InvalidInvitationException e) {
            throw Problem.INVALID_REQUEST.raise();
        }
        Invitation invitation = issued.invitation();
        responses.json(exchange, HttpStatus.CREATED, Responses.object(
                "invitationId", invitation.id().toString(),
                "tenantId", invitation.tenantId().toString(),
                "email", invitation.email(),
                "role", invitation.role(),
                "expiresAt", invitation.expiresAt().toString(),
                "token", issued.rawToken()));
    }

    /**
     * Creates the account of the invitee and makes it a member of the invitation's tenant, with the
     * invitation's role.
     *
     * <p>The pending invitation is looked up first, so no account is created for a caller that does not
     * hold the token. The account is then created verified, because the token reached the address, and the
     * invitation is consumed in one conditional write that checks the token, tenant and address again.
     */
    void accept(HttpExchange exchange) {
        JsonBodies.Fields body = bodies.read(exchange, Set.of("tenantId", "token", "email", "password"));
        UUID tenant = body.uuid("tenantId");
        String token = body.string("token", MAX_TOKEN);
        String email = body.string("email", MAX_EMAIL);
        char[] password = body.password("password");
        try {
            Invitation consumed = TenantScope.call(tenant, () -> acceptInTenant(tenant, token, email, password));
            responses.json(exchange, HttpStatus.CREATED, Responses.object(
                    "tenantId", consumed.tenantId().toString(),
                    "role", consumed.role()));
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private Invitation acceptInTenant(UUID tenant, String token, String email, char[] password) {
        if (services.invitations().findPending(token, tenant, email).isEmpty()) {
            throw Problem.INVALID_INVITATION.raise();
        }
        UUID subject = UUID.randomUUID();
        try {
            services.credentialProvisioning().provisionVerified(subject, email, password.clone());
        } catch (CredentialAlreadyExistsException e) {
            throw Problem.ACCOUNT_EXISTS.raise();
        } catch (IllegalArgumentException e) {
            throw Problem.INVALID_PASSWORD.raise();
        }
        Invitation consumed;
        try {
            consumed = services.invitations().consume(token, tenant, email);
        } catch (InvalidInvitationException e) {
            throw Problem.INVALID_INVITATION.raise();
        }
        services.memberships().grant(consumed.tenantId(), subject, consumed.role());
        return consumed;
    }
}
