package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.auth.Membership;
import eu.exeris.sku.identity.auth.MembershipDirectory;

import java.util.List;
import java.util.UUID;

/**
 * Stands in for the host's directory in a non-production environment that names none. Nobody belongs to
 * any tenant, so tokens carry no tenant, and no membership can be granted.
 */
final class UnconfiguredMembershipDirectory implements MembershipDirectory {

    @Override
    public List<Membership> memberships(UUID subjectId) {
        return List.of();
    }

    @Override
    public void grant(UUID tenantId, UUID subjectId, String role) {
        throw new IllegalStateException("no membership directory is configured");
    }
}
