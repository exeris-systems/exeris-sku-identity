package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.IdentityHarness;
import eu.exeris.sku.identity.support.TestConfig;
import eu.exeris.sku.identity.support.TestExchange;
import eu.exeris.sku.identity.support.TransactionalOutboxDelivery;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static eu.exeris.sku.identity.support.IdentityHarness.bearer;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * A host part loaded by class name through the launcher's plan writes to the database from inside the
 * issue transaction, through the executor the launcher hands it.
 */
@DisplayName("A launcher-loaded host part joins the service's transactions")
class HostPartTransactionsIT {

    private static TransactionalOutboxDelivery part;
    private static IdentityHarness service;

    @BeforeAll
    static void start() throws Exception {
        Map<String, String> env = new HashMap<>(TestConfig.env());
        env.put("EXERIS_DATABASE_URL", "jdbc:postgresql://db.example.test:5432/identity");
        env.put("EXERIS_DATABASE_USER", "identity_service");
        env.put("EXERIS_DATABASE_PASSWORD", TestConfig.randomBase64(12));
        env.put("EXERIS_ENVIRONMENT", "development");
        env.put("EXERIS_IDENTITY_INVITATION_DELIVERY", TransactionalOutboxDelivery.class.getName());
        StartupPlan plan = StartupPlan.prepare(env);
        part = (TransactionalOutboxDelivery) plan.invitationDelivery();

        service = IdentityHarness.start(part);
        try (Connection owner = service.database.owner(); Statement statement = owner.createStatement()) {
            statement.execute("CREATE TABLE " + TransactionalOutboxDelivery.TABLE + " (recipient TEXT NOT NULL)");
            statement.execute("GRANT SELECT, INSERT ON " + TransactionalOutboxDelivery.TABLE + " TO "
                    + eu.exeris.sku.identity.support.PostgresSupport.serviceRole());
        }
        plan.joinTransactions(service.composition.transactionalExecutor());
    }

    @AfterAll
    static void stop() {
        service.close();
    }

    private static long count(String sql, String parameter) throws SQLException {
        try (Connection owner = service.database.owner(); PreparedStatement statement = owner.prepareStatement(sql)) {
            statement.setString(1, parameter);
            try (ResultSet rows = statement.executeQuery()) {
                rows.next();
                return rows.getLong(1);
            }
        }
    }

    private static TestExchange issue(String email) {
        String admin = service.accessToken(service.member(UUID.randomUUID(), "admin"));
        return service.post("/api/v1/auth/invitations", Map.of("email", email, "role", "member"), bearer(admin));
    }

    private static String address() {
        return "invitee-" + UUID.randomUUID().toString().substring(0, 10) + "@example.test";
    }

    @Test
    @DisplayName("the outbox row commits with the invitation")
    void rowCommitsWithTheInvitation() throws Exception {
        String email = address();

        assertThat(issue(email).code()).isEqualTo(201);

        assertThat(count("SELECT count(*) FROM " + TransactionalOutboxDelivery.TABLE + " WHERE recipient = ?", email))
                .isEqualTo(1);
        assertThat(count("SELECT count(*) FROM invitations WHERE lower(email) = lower(?)", email)).isEqualTo(1);
    }

    @Test
    @DisplayName("the outbox row rolls back with the invitation when the delivery fails after writing it")
    void rowRollsBackWithTheInvitation() throws Exception {
        String email = address();
        part.failAfterWrite();
        try {
            assertThat(issue(email).code()).isEqualTo(502);
        } finally {
            part.stopFailing();
        }

        assertThat(count("SELECT count(*) FROM " + TransactionalOutboxDelivery.TABLE + " WHERE recipient = ?", email))
                .isZero();
        assertThat(count("SELECT count(*) FROM invitations WHERE lower(email) = lower(?)", email)).isZero();
    }
}
