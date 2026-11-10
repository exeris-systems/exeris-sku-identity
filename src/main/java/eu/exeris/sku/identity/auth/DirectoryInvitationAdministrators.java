package eu.exeris.sku.identity.auth;

import eu.exeris.caps.invitations.spi.InvitationAdministrators;

import java.util.Objects;
import java.util.UUID;

/** Lets a subject administer a tenant's invitations when the directory gives it an administering role there. */
public final class DirectoryInvitationAdministrators implements InvitationAdministrators {

    private final MembershipDirectory directory;

    /**
     * @param directory where memberships live
     */
    public DirectoryInvitationAdministrators(MembershipDirectory directory) {
        this.directory = Objects.requireNonNull(directory, "directory must not be null");
    }

    @Override
    public boolean mayAdminister(UUID tenantId, UUID subjectId) {
        if (tenantId == null || subjectId == null) {
            return false;
        }
        return directory.memberships(subjectId).stream()
                .anyMatch(m -> tenantId.equals(m.tenantId()) && RoleScopes.mayAdminister(m.role()));
    }
}
