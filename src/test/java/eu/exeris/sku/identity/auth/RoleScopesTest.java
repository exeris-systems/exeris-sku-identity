package eu.exeris.sku.identity.auth;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("RoleScopes.issuable")
class RoleScopesTest {

    @Test
    @DisplayName("the roles the service knows are issuable")
    void knownRoles() {
        assertThat(RoleScopes.issuable("owner")).isTrue();
        assertThat(RoleScopes.issuable("admin")).isTrue();
        assertThat(RoleScopes.issuable("member")).isTrue();
        assertThat(RoleScopes.issuable("billing-contact")).isTrue();
    }

    @Test
    @DisplayName("the platform role is not issuable however it is written")
    void platformRole() {
        assertThat(RoleScopes.issuable("platform-admin")).isFalse();
        assertThat(RoleScopes.issuable("Platform-Admin")).isFalse();
        assertThat(RoleScopes.issuable(" platform-admin")).isFalse();
        assertThat(RoleScopes.issuable("PLATFORM-ADMIN\t")).isFalse();
    }

    @Test
    @DisplayName("a role that is unknown or not exactly in the known form is not issuable")
    void unknownRoles() {
        assertThat(RoleScopes.issuable(null)).isFalse();
        assertThat(RoleScopes.issuable("")).isFalse();
        assertThat(RoleScopes.issuable("Admin")).isFalse();
        assertThat(RoleScopes.issuable("owner ")).isFalse();
        assertThat(RoleScopes.issuable("1admin")).isFalse();
        assertThat(RoleScopes.issuable("has space")).isFalse();
        assertThat(RoleScopes.issuable("a".repeat(33))).isFalse();
    }
}
