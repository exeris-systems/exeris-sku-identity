package eu.exeris.sku.identity.auth;

import java.util.Objects;
import java.util.UUID;

/**
 * One subject's role in one tenant, as the host's {@link MembershipDirectory} records it.
 *
 * @param tenantId the tenant the role applies in
 * @param role     the role name; compared case-sensitively and never empty
 */
public record Membership(UUID tenantId, String role) {

    public Membership {
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(role, "role must not be null");
        if (role.isBlank()) {
            throw new IllegalArgumentException("role must not be blank");
        }
    }
}
