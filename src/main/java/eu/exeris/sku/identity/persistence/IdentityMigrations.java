package eu.exeris.sku.identity.persistence;

import eu.exeris.caps.credentialstore.CredentialStoreModule;
import eu.exeris.caps.federatedlogin.FederatedLoginModule;
import eu.exeris.caps.invitations.InvitationsModule;
import eu.exeris.caps.mfatotp.MfaTotpModule;
import eu.exeris.caps.sessionmanagement.SessionManagementModule;
import eu.exeris.caps.tokenissuer.TokenIssuerModule;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * The schema migrations of every capability this service composes, in the order they apply, and the
 * runner that applies them.
 *
 * <p>The runner records each applied resource in {@value #TRACKING_TABLE}, so applying the list again
 * applies only what is new. Each resource and its record are one transaction, and concurrent runners
 * are serialised by an advisory lock. It runs with a role that may create tables and policies, never
 * with the role the service itself connects as.
 */
public final class IdentityMigrations {

    /** The table recording which migration resources have been applied. */
    public static final String TRACKING_TABLE = "identity_applied_migrations";

    private static final long ADVISORY_LOCK_KEY = 0x1D3A_7157_0000_0001L;

    private static final List<String> RESOURCES = orderedResources();

    private IdentityMigrations() {
    }

    /**
     * The classpath resources to apply, in order.
     *
     * @return an immutable list of resource paths
     */
    public static List<String> resources() {
        return RESOURCES;
    }

    /**
     * Applies every migration that has not been applied to the database behind the connection.
     *
     * @param connection a connection of a role allowed to create tables, indexes and policies; its
     *                   auto-commit mode is changed during the call and restored afterwards
     * @return the resources applied by this call, in order; empty when the schema was current
     * @throws SQLException when a migration fails; the failing resource is rolled back and nothing after
     *                      it runs
     */
    public static List<String> apply(Connection connection) throws SQLException {
        boolean autoCommit = connection.getAutoCommit();
        connection.setAutoCommit(false);
        List<String> applied = new ArrayList<>();
        try {
            try (Statement statement = connection.createStatement()) {
                statement.execute("SELECT pg_advisory_xact_lock(" + ADVISORY_LOCK_KEY + ")");
                statement.execute("CREATE TABLE IF NOT EXISTS " + TRACKING_TABLE
                        + " (resource TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())");
            }
            connection.commit();
            for (String resource : RESOURCES) {
                try (Statement statement = connection.createStatement()) {
                    statement.execute("SELECT pg_advisory_xact_lock(" + ADVISORY_LOCK_KEY + ")");
                }
                if (isApplied(connection, resource)) {
                    connection.rollback();
                    continue;
                }
                try (Statement statement = connection.createStatement()) {
                    statement.execute(read(resource));
                }
                try (PreparedStatement record = connection.prepareStatement(
                        "INSERT INTO " + TRACKING_TABLE + " (resource) VALUES (?)")) {
                    record.setString(1, resource);
                    record.executeUpdate();
                }
                connection.commit();
                applied.add(resource);
            }
            return List.copyOf(applied);
        } catch (SQLException | RuntimeException e) {
            connection.rollback();
            throw e;
        } finally {
            connection.setAutoCommit(autoCommit);
        }
    }

    private static boolean isApplied(Connection connection, String resource) throws SQLException {
        try (PreparedStatement query = connection.prepareStatement(
                "SELECT 1 FROM " + TRACKING_TABLE + " WHERE resource = ?")) {
            query.setString(1, resource);
            try (ResultSet rows = query.executeQuery()) {
                return rows.next();
            }
        }
    }

    private static String read(String resource) {
        try (InputStream in = IdentityMigrations.class.getClassLoader().getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("migration resource is not on the classpath: " + resource);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("migration resource cannot be read: " + resource, e);
        }
    }

    private static List<String> orderedResources() {
        List<String> all = new ArrayList<>();
        all.addAll(CredentialStoreModule.MIGRATIONS);
        all.addAll(SessionManagementModule.MIGRATIONS);
        all.addAll(MfaTotpModule.MIGRATIONS);
        all.addAll(TokenIssuerModule.MIGRATIONS);
        all.addAll(InvitationsModule.MIGRATIONS);
        all.addAll(FederatedLoginModule.MIGRATIONS);
        return List.copyOf(all);
    }
}
