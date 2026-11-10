package eu.exeris.sku.identity.auth;

import java.util.List;
import java.util.UUID;

/**
 * Where tenant membership and role grants live. The host that owns tenants implements it; this service
 * keeps no membership table of its own.
 *
 * <p>Implementations are called from request threads and must be thread-safe. Neither method may block
 * for longer than a request is allowed to take, and neither may return or throw anything that discloses
 * another subject's memberships.
 */
public interface MembershipDirectory {

    /**
     * The tenants the subject belongs to, with the subject's role in each.
     *
     * @param subjectId the account
     * @return every membership of the subject; empty when it has none, never null
     */
    List<Membership> memberships(UUID subjectId);

    /**
     * Records that the subject holds the role in the tenant. Granting a role the subject already holds in
     * that tenant changes nothing; granting a different role replaces the previous one.
     *
     * <p>It is called while an invitation is being accepted, before the account and the invitation are
     * committed together. It may therefore be called again for the same tenant, subject and role, and a
     * grant may remain for a subject whose account was never committed; such a subject has no credential,
     * so the grant opens nothing, and the next acceptance of the same invitation creates the same subject
     * and finds the grant already there.
     *
     * <p>An implementation that writes to the service's database must write through the executor that joins
     * the acceptance's transaction, so that its write is part of the acceptance. A host part named to the
     * launcher receives that executor by implementing {@link JoinsServiceTransactions}; a host that embeds
     * the library reads it from {@link eu.exeris.sku.identity.IdentityComposition#transactionalExecutor()}.
     * A write through any other executor is not part of the acceptance: on the connection the request
     * already holds it is refused and rolls the acceptance back, and under another storage context it
     * commits on its own and outlives a rollback. Reads need no such care.
     *
     * @param tenantId  the tenant
     * @param subjectId the account
     * @param role      the role to hold
     */
    void grant(UUID tenantId, UUID subjectId, String role);
}
