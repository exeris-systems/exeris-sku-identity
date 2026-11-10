package eu.exeris.sku.identity.auth;

import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("DirectoryInvitationAdministrators and RoleScopes")
class DirectoryInvitationAdministratorsTest {

    private final InMemoryMembershipDirectory directory = new InMemoryMembershipDirectory();
    private final DirectoryInvitationAdministrators administrators = new DirectoryInvitationAdministrators(directory);
    private final UUID tenant = UUID.randomUUID();
    private final UUID subject = UUID.randomUUID();

    @Test
    @DisplayName("an owner or admin of the tenant may administer it, any other role or tenant may not")
    void onlyAdministeringRolesInTheTenant() {
        assertThat(administrators.mayAdminister(tenant, subject)).isFalse();

        directory.grant(tenant, subject, "member");
        assertThat(administrators.mayAdminister(tenant, subject)).isFalse();

        directory.grant(tenant, subject, "admin");
        assertThat(administrators.mayAdminister(tenant, subject)).isTrue();
        assertThat(administrators.mayAdminister(UUID.randomUUID(), subject)).isFalse();

        directory.grant(tenant, subject, "owner");
        assertThat(administrators.mayAdminister(tenant, subject)).isTrue();
        assertThat(administrators.mayAdminister(tenant, null)).isFalse();
        assertThat(administrators.mayAdminister(null, subject)).isFalse();
    }

    @Test
    @DisplayName("only administering roles carry the invitation scope")
    void scopesFollowRoles() {
        assertThat(RoleScopes.scopesOf("owner")).containsExactly(Scopes.INVITATIONS_WRITE);
        assertThat(RoleScopes.scopesOf("admin")).containsExactly(Scopes.INVITATIONS_WRITE);
        assertThat(RoleScopes.scopesOf("member")).isEmpty();
        assertThat(RoleScopes.scopesOf("platform-admin")).isEmpty();
    }

    @Test
    @DisplayName("a token names a tenant only when the subject has exactly one membership")
    void activeMembershipNeedsExactlyOne() {
        Membership only = new Membership(tenant, "admin");

        assertThat(RoleScopes.activeMembership(List.of(only))).contains(only);
        assertThat(RoleScopes.activeMembership(List.of())).isEmpty();
        assertThat(RoleScopes.activeMembership(List.of(only, new Membership(UUID.randomUUID(), "admin")))).isEmpty();
        assertThat(RoleScopes.activeMembership(null)).isEmpty();
    }
}
