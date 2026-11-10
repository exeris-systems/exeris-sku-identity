package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.config.IdentityConfigException;
import eu.exeris.sku.identity.persistence.IdentityMigrations;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The {@code migrate} subcommand: applies the capabilities' schema with a role that may create tables,
 * which is never the role the service runs as, then lets the service role use what was created.
 */
final class Migrate {

    static final String DATABASE_PREFIX = "EXERIS_MIGRATE_DATABASE";
    static final String SERVICE_ROLE = "EXERIS_MIGRATE_SERVICE_ROLE";

    private static final Pattern ROLE_NAME = Pattern.compile("[a-z_][a-z0-9_]{0,62}");

    private Migrate() {
    }

    /**
     * Applies the migrations.
     *
     * @param environment the process environment
     * @return the resources applied, in order; empty when the schema was current
     * @throws IdentityConfigException when a setting is missing or unusable
     * @throws SQLException            when the database refuses a statement
     */
    static List<String> run(Map<String, String> environment) throws SQLException {
        LauncherEnvironment in = new LauncherEnvironment(environment);
        DatabaseSettings database = DatabaseSettings.read(in, DATABASE_PREFIX);
        String role = in.optional(SERVICE_ROLE);
        if (role != null && !ROLE_NAME.matcher(role).matches()) {
            in.problem(SERVICE_ROLE + " must be a lowercase role name of letters, digits and underscores.");
        }
        if (!in.problems().isEmpty()) {
            throw new IdentityConfigException(in.problems());
        }
        try (Connection connection = database.open()) {
            List<String> applied = IdentityMigrations.apply(connection);
            if (role != null) {
                allow(connection, role);
            }
            return applied;
        }
    }

    /** The service role reads and writes the capabilities' tables and never the migration record. */
    private static void allow(Connection connection, String role) throws SQLException {
        String quoted = "\"" + role + "\"";
        try (Statement statement = connection.createStatement()) {
            statement.execute("GRANT USAGE ON SCHEMA public TO " + quoted);
            statement.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO " + quoted);
            statement.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO " + quoted);
            statement.execute("REVOKE ALL ON TABLE " + IdentityMigrations.TRACKING_TABLE + " FROM " + quoted);
        }
    }
}
