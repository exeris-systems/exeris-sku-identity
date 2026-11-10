package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.persistence.IdentityMigrations;
import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.TestConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("migrate subcommand in a process")
class MigrateProcessIT {

    private static Map<String, String> environment(PostgresSupport.Database database, boolean grantServiceRole) {
        Map<String, String> env = new java.util.HashMap<>();
        env.put("EXERIS_MIGRATE_DATABASE_URL", database.ownerUrl());
        env.put("EXERIS_MIGRATE_DATABASE_USER", database.ownerUser());
        env.put("EXERIS_MIGRATE_DATABASE_PASSWORD", database.ownerPassword());
        if (grantServiceRole) {
            env.put("EXERIS_MIGRATE_SERVICE_ROLE", PostgresSupport.serviceRole());
        }
        return env;
    }

    private static int run(Map<String, String> env, String[] output) throws Exception {
        try (LaunchedProcess process = LaunchedProcess.start(env, "migrate")) {
            int status = process.awaitExit(60);
            output[0] = process.output();
            return status;
        }
    }

    private static List<String> tables(Connection connection) throws SQLException {
        List<String> names = new ArrayList<>();
        try (Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename")) {
            while (rows.next()) {
                names.add(rows.getString(1));
            }
        }
        return names;
    }

    private static boolean mayRead(Connection connection, String table) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet row = statement.executeQuery(
                     "SELECT has_table_privilege(current_user, 'public." + table + "', 'SELECT')")) {
            row.next();
            return row.getBoolean(1);
        }
    }

    @Test
    @DisplayName("Creates the schema with the privileged role, lets the service role use it, and is a no-op the second time")
    void appliesOnceAndGrantsTheServiceRole() throws Exception {
        PostgresSupport.Database database = PostgresSupport.emptyDatabase();
        String[] output = new String[1];

        assertThat(run(environment(database, true), output)).as(output[0]).isZero();
        assertThat(output[0]).contains("Applied " + IdentityMigrations.resources().size() + " migration(s)");

        try (Connection owner = database.owner()) {
            List<String> tables = tables(owner);
            assertThat(tables).contains(IdentityMigrations.TRACKING_TABLE);
            assertThat(tables.size()).isGreaterThan(5);
        }
        try (Connection service = database.service()) {
            for (String table : tables(service)) {
                if (table.equals(IdentityMigrations.TRACKING_TABLE)) {
                    assertThat(mayRead(service, table)).as("service role reads the migration record").isFalse();
                } else {
                    assertThat(mayRead(service, table)).as("service role reads " + table).isTrue();
                }
            }
        }

        assertThat(run(environment(database, true), output)).as(output[0]).isZero();
        assertThat(output[0]).contains("nothing to apply");
    }

    @Test
    @DisplayName("Without the database settings it exits with the configuration status and touches nothing")
    void incompleteConfigurationIsRefused() throws Exception {
        String[] output = new String[1];

        int status = run(Map.of("EXERIS_MIGRATE_DATABASE_PASSWORD", TestConfig.randomBase64(8)), output);

        assertThat(status).as(output[0]).isEqualTo(IdentitySkuApplication.EXIT_CONFIG);
        assertThat(output[0]).contains("EXERIS_MIGRATE_DATABASE_URL").contains("EXERIS_MIGRATE_DATABASE_USER");
    }

    @Test
    @DisplayName("A role that may not create tables fails the migration and exits non-zero")
    void migrationFailureExitsNonZero() throws Exception {
        PostgresSupport.Database database = PostgresSupport.emptyDatabase();
        Map<String, String> env = environment(database, false);
        env.put("EXERIS_MIGRATE_DATABASE_USER", database.serviceUser());
        env.put("EXERIS_MIGRATE_DATABASE_PASSWORD", database.servicePassword());
        String[] output = new String[1];

        assertThat(run(env, output)).as(output[0]).isEqualTo(IdentitySkuApplication.EXIT_MIGRATION_FAILED);
    }
}
