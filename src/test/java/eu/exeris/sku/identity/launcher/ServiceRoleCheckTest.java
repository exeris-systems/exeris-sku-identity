package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.config.IdentityConfigException;
import eu.exeris.sku.identity.support.PostgresSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.sql.SQLException;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Service role: row-level security must apply to it")
class ServiceRoleCheckTest {

    @Test
    @DisplayName("The unprivileged service role passes; a superuser is refused")
    void superuserIsRefused() throws SQLException {
        PostgresSupport.Database database = PostgresSupport.newDatabase();

        assertThatCode(() -> ServiceRoleCheck.verify(new DatabaseSettings(
                database.serviceUrl(), database.serviceUser(), database.servicePassword()))).doesNotThrowAnyException();
        assertThatThrownBy(() -> ServiceRoleCheck.verify(new DatabaseSettings(
                database.ownerUrl(), database.ownerUser(), database.ownerPassword())))
                .isInstanceOf(IdentityConfigException.class)
                .hasMessageContaining("NOSUPERUSER and NOBYPASSRLS");
    }

    @Test
    @DisplayName("A role that bypasses row-level security is refused")
    void bypassIsRefused() throws SQLException {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        String role = "bypass_" + Long.toHexString(System.nanoTime());
        String secret = Long.toHexString(System.nanoTime());
        try (var owner = database.owner(); var statement = owner.createStatement()) {
            statement.execute("CREATE ROLE " + role + " LOGIN PASSWORD '" + secret + "' NOSUPERUSER BYPASSRLS");
        }

        assertThatThrownBy(() -> ServiceRoleCheck.verify(new DatabaseSettings(database.ownerUrl(), role, secret)))
                .isInstanceOf(IdentityConfigException.class);
    }
}
