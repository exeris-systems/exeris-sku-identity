package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.IdentityHarness;
import eu.exeris.sku.identity.support.PostgresSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("What the service role finds before the first account is created")
class DatabaseStateIT {

    private static DatabaseSettings as(PostgresSupport.Database database) {
        return new DatabaseSettings(database.serviceUrl(), database.serviceUser(), database.servicePassword());
    }

    @Test
    @DisplayName("A database nobody migrated is NOT_MIGRATED and stays untouched")
    void notMigrated() throws Exception {
        PostgresSupport.Database database = PostgresSupport.emptyDatabase();

        assertThat(DatabaseState.inspect(as(database))).isEqualTo(DatabaseState.State.NOT_MIGRATED);
        assertThat(BootstrapOwnerSupport.tables(database)).isEmpty();
    }

    @Test
    @DisplayName("A migrated database with no account is EMPTY")
    void empty() throws Exception {
        assertThat(DatabaseState.inspect(as(PostgresSupport.newDatabase()))).isEqualTo(DatabaseState.State.EMPTY);
    }

    @Test
    @DisplayName("A migrated database with an account is HAS_ACCOUNTS")
    void hasAccounts() throws Exception {
        try (IdentityHarness service = IdentityHarness.start()) {
            service.account();

            assertThat(DatabaseState.inspect(as(service.database))).isEqualTo(DatabaseState.State.HAS_ACCOUNTS);
        }
    }

    @Test
    @DisplayName("A role that may not read or may not insert is NOT_MIGRATED, even when accounts exist")
    void missingPrivilege() throws Exception {
        try (IdentityHarness service = IdentityHarness.start()) {
            service.account();
            for (String revoked : new String[] {"SELECT", "INSERT"}) {
                try (Connection owner = service.database.owner(); Statement statement = owner.createStatement()) {
                    statement.execute("REVOKE " + revoked + " ON credential_records FROM "
                            + PostgresSupport.serviceRole());
                }

                assertThat(DatabaseState.inspect(as(service.database))).as(revoked)
                        .isEqualTo(DatabaseState.State.NOT_MIGRATED);

                try (Connection owner = service.database.owner(); Statement statement = owner.createStatement()) {
                    statement.execute("GRANT " + revoked + " ON credential_records TO " + PostgresSupport.serviceRole());
                }
            }
            assertThat(DatabaseState.inspect(as(service.database))).isEqualTo(DatabaseState.State.HAS_ACCOUNTS);
        }
    }

    @Test
    @DisplayName("An unreachable database is an SQLException")
    void unreachable() throws Exception {
        PostgresSupport.Database database = PostgresSupport.emptyDatabase();
        DatabaseSettings wrongPassword = new DatabaseSettings(database.serviceUrl(), database.serviceUser(),
                "not-" + database.servicePassword());

        assertThatThrownBy(() -> DatabaseState.inspect(wrongPassword)).isInstanceOf(SQLException.class);
    }
}
