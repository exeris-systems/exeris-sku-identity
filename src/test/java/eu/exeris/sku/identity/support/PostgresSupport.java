package eu.exeris.sku.identity.support;

import eu.exeris.sku.identity.persistence.IdentityMigrations;
import org.testcontainers.containers.PostgreSQLContainer;

import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HexFormat;

/**
 * One PostgreSQL container per test JVM. Each caller gets its own database, with the capabilities'
 * migrations applied by the container's superuser and a service role that is neither superuser nor allowed
 * to bypass row-level security.
 */
public final class PostgresSupport {

    private static final String SERVICE_ROLE = "identity_service";
    private static final PostgreSQLContainer<?> CONTAINER = new PostgreSQLContainer<>("postgres:16-alpine");
    private static final SecureRandom RANDOM = new SecureRandom();
    private static String servicePassword;

    private PostgresSupport() {
    }

    /**
     * A migrated database.
     *
     * @param ownerUrl        JDBC URL for the superuser
     * @param ownerUser       the superuser
     * @param ownerPassword   the superuser's password
     * @param serviceUrl      JDBC URL for the service role
     * @param serviceUser     the service role
     * @param servicePassword the service role's password
     */
    public record Database(String ownerUrl, String ownerUser, String ownerPassword,
                           String serviceUrl, String serviceUser, String servicePassword) {

        /** Opens a superuser connection. */
        public Connection owner() throws SQLException {
            return DriverManager.getConnection(ownerUrl, ownerUser, ownerPassword);
        }

        /** Opens a connection as the service role. */
        public Connection service() throws SQLException {
            return DriverManager.getConnection(serviceUrl, serviceUser, servicePassword);
        }
    }

    /**
     * Creates a database and applies every migration to it.
     *
     * @return the new database
     * @throws SQLException when the database cannot be prepared
     */
    public static synchronized Database newDatabase() throws SQLException {
        Database database = emptyDatabase();
        try (Connection owner = database.owner()) {
            IdentityMigrations.apply(owner);
            try (Statement statement = owner.createStatement()) {
                statement.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "
                        + SERVICE_ROLE);
                statement.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO " + SERVICE_ROLE);
                statement.execute("REVOKE ALL ON TABLE " + IdentityMigrations.TRACKING_TABLE + " FROM "
                        + SERVICE_ROLE);
            }
        }
        return database;
    }

    /**
     * Creates a database with nothing in it. The service role exists and owns nothing.
     *
     * @return the new database
     * @throws SQLException when the database cannot be prepared
     */
    public static synchronized Database emptyDatabase() throws SQLException {
        if (!CONTAINER.isRunning()) {
            CONTAINER.start();
        }
        String name = "identity_" + HexFormat.of().formatHex(randomBytes(6));
        try (Connection admin = DriverManager.getConnection(CONTAINER.getJdbcUrl(), CONTAINER.getUsername(),
                CONTAINER.getPassword());
             Statement statement = admin.createStatement()) {
            statement.execute("CREATE DATABASE " + name);
            if (servicePassword == null) {
                servicePassword = HexFormat.of().formatHex(randomBytes(16));
                statement.execute("CREATE ROLE " + SERVICE_ROLE + " LOGIN PASSWORD '" + servicePassword
                        + "' NOSUPERUSER NOBYPASSRLS");
            }
        }
        String ownerUrl = urlFor(name);
        return new Database(ownerUrl, CONTAINER.getUsername(), CONTAINER.getPassword(),
                ownerUrl, SERVICE_ROLE, servicePassword);
    }

    /** The name of the service role every database grants to. */
    public static String serviceRole() {
        return SERVICE_ROLE;
    }

    private static String urlFor(String database) {
        return "jdbc:postgresql://" + CONTAINER.getHost() + ":" + CONTAINER.getMappedPort(5432) + "/" + database;
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }
}
