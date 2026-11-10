package eu.exeris.sku.identity.persistence;

import eu.exeris.sku.identity.support.PostgresSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("IdentityMigrations")
class IdentityMigrationsTest {

    @Test
    @DisplayName("every capability's migration is listed once, and each is on the classpath")
    void listsEveryMigration() {
        assertThat(IdentityMigrations.resources())
                .hasSize(6)
                .doesNotHaveDuplicates()
                .allSatisfy(resource -> assertThat(IdentityMigrationsTest.class.getClassLoader().getResource(resource))
                        .as(resource).isNotNull());
    }

    @Test
    @DisplayName("applying twice applies nothing the second time, and the service role cannot bypass row-level security")
    void appliesOnce() throws SQLException {
        PostgresSupport.Database database = PostgresSupport.newDatabase();

        try (Connection owner = database.owner()) {
            assertThat(IdentityMigrations.apply(owner)).isEmpty();
            try (Statement statement = owner.createStatement();
                 ResultSet rows = statement.executeQuery("SELECT count(*) FROM " + IdentityMigrations.TRACKING_TABLE)) {
                rows.next();
                assertThat(rows.getInt(1)).isEqualTo(IdentityMigrations.resources().size());
            }
            try (Statement statement = owner.createStatement();
                 ResultSet rows = statement.executeQuery(
                         "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = '" + database.serviceUser() + "'")) {
                rows.next();
                assertThat(rows.getBoolean(1)).isFalse();
                assertThat(rows.getBoolean(2)).isFalse();
            }
        }
        try (Connection service = database.service(); Statement statement = service.createStatement()) {
            assertThatThrownBy(() -> statement.executeQuery("SELECT * FROM " + IdentityMigrations.TRACKING_TABLE))
                    .isInstanceOf(SQLException.class);
        }
    }
}
