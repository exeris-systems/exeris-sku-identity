package eu.exeris.sku.identity.wiring;

import eu.exeris.caps.sessionmanagement.api.IssuedAccessToken;
import eu.exeris.caps.sessionmanagement.spi.AccessTokenIssuer;
import eu.exeris.caps.tokenissuer.api.TokenIssueRequest;
import eu.exeris.sku.identity.auth.Membership;
import eu.exeris.sku.identity.auth.MembershipDirectory;
import eu.exeris.sku.identity.auth.RoleScopes;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

/**
 * Issues the access tokens the session store hands out, naming the tenant, role and scopes the
 * membership directory gives the subject.
 *
 * <p>The same rule applies at login and at refresh, so a token's tenant never changes between the two. See
 * {@link RoleScopes#activeMembership} for how the tenant is chosen.
 */
public final class SessionTokenIssuerAdapter implements AccessTokenIssuer {

    /** The claim carrying the space-separated scopes. */
    static final String SCOPE_CLAIM = "scope";

    private final eu.exeris.caps.tokenissuer.api.AccessTokenIssuer issuer;
    private final MembershipDirectory directory;

    /**
     * @param issuer    the token issuer that signs
     * @param directory where memberships live
     */
    public SessionTokenIssuerAdapter(eu.exeris.caps.tokenissuer.api.AccessTokenIssuer issuer,
                                     MembershipDirectory directory) {
        this.issuer = Objects.requireNonNull(issuer, "issuer must not be null");
        this.directory = Objects.requireNonNull(directory, "directory must not be null");
    }

    @Override
    public IssuedAccessToken issueAccessToken(UUID subjectId, UUID sessionId) {
        TokenIssueRequest.Builder request = TokenIssueRequest.builder()
                .subjectId(subjectId)
                .sessionId(sessionId);
        Optional<Membership> active = RoleScopes.activeMembership(directory.memberships(subjectId));
        if (active.isPresent()) {
            Membership membership = active.get();
            request.tenantId(membership.tenantId().toString()).roles(Set.of(membership.role()));
            Set<String> scopes = new TreeSet<>(RoleScopes.scopesOf(membership.role()));
            if (!scopes.isEmpty()) {
                request.customClaims(Map.of(SCOPE_CLAIM, String.join(" ", scopes)));
            }
        }
        eu.exeris.caps.tokenissuer.api.IssuedAccessToken issued = issuer.issueAccessToken(request.build());
        return new IssuedAccessToken(issued.token(), issued.expiresAt(), issued.tokenType());
    }
}
