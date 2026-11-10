package eu.exeris.sku.identity.http;

import eu.exeris.caps.audittrail.api.AuditQuery;
import eu.exeris.sku.identity.support.IdentityHarness;
import eu.exeris.sku.identity.support.InMemoryMembershipDirectory.Grant;
import eu.exeris.sku.identity.support.TestConfig;
import eu.exeris.sku.identity.support.TestExchange;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static eu.exeris.sku.identity.support.IdentityHarness.bearer;
import static eu.exeris.sku.identity.support.IdentityHarness.json;
import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Accepting an invitation is all or nothing")
class InvitationAcceptanceAtomicityIT {

    private static final String BASE = "/api/v1/auth";
    private static final String INVALID_INVITATION = "{\"error\":\"invalid_invitation\"}";

    private static IdentityHarness service;

    @BeforeAll
    static void start() throws Exception {
        service = IdentityHarness.start();
    }

    @AfterAll
    static void stop() {
        service.close();
    }

    private record Issued(UUID tenant, UUID invitationId, String email, String token) {
    }

    private static Issued issue(String role) {
        UUID tenant = UUID.randomUUID();
        String admin = service.accessToken(service.member(tenant, "admin"));
        String email = "invitee-" + UUID.randomUUID().toString().substring(0, 10) + "@example.test";
        TestExchange issued = service.post(BASE + "/invitations", Map.of("email", email, "role", role), bearer(admin));
        assertThat(issued.code()).isEqualTo(201);
        UUID id = UUID.fromString(json(issued).get("invitationId").stringValue());
        return new Issued(tenant, id, email, service.invitations.tokenFor(email));
    }

    private static TestExchange accept(Issued invitation, String password) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("tenantId", invitation.tenant().toString());
        body.put("token", invitation.token());
        body.put("email", invitation.email());
        body.put("password", password);
        return service.post(BASE + "/invitations/accept", body);
    }

    private static String password() {
        return new String(TestConfig.randomPassword());
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

    private static long credentials(String email) throws SQLException {
        return count("SELECT count(*) FROM credential_records WHERE lower(login_identifier) = lower(?)", email);
    }

    private static long pending(Issued invitation) throws SQLException {
        return count("SELECT count(*) FROM invitations WHERE consumed_at IS NULL AND id = ?::uuid",
                invitation.invitationId().toString());
    }

    private static long provisioningEvents(UUID subject) {
        return service.composition.services().audit().count(AuditQuery.builder()
                .resourceId(subject.toString()).action("CREDENTIAL_PROVISIONED").build());
    }

    private static List<Grant> grantsFor(UUID subject) {
        return service.directory.grants().stream().filter(g -> g.subjectId().equals(subject)).toList();
    }

    private static String tenantClaim(TestExchange login) {
        String payload = json(login).get("accessToken").stringValue().split("\\.")[1];
        return new String(Base64.getUrlDecoder().decode(payload));
    }

    @Test
    @DisplayName("a directory that fails leaves no account, no audit event and a pending invitation, and a retry completes")
    void directoryFailureLeavesNothing() throws Exception {
        Issued invitation = issue("member");
        UUID subject = InvitationHandlers.subjectOf(invitation.invitationId());
        String password = password();
        service.directory.failNextGrant();

        TestExchange failed = accept(invitation, password);

        assertThat(failed.code()).isEqualTo(500);
        assertThat(pending(invitation)).isEqualTo(1);
        assertThat(credentials(invitation.email())).isZero();
        assertThat(provisioningEvents(subject)).isZero();
        assertThat(service.post(BASE + "/login", Map.of("email", invitation.email(), "password", password)).code())
                .isEqualTo(401);

        TestExchange retried = accept(invitation, password);

        assertThat(retried.code()).isEqualTo(201);
        assertThat(provisioningEvents(subject)).isEqualTo(1);
        TestExchange login = service.post(BASE + "/login", Map.of("email", invitation.email(), "password", password));
        assertThat(login.code()).isEqualTo(200);
        assertThat(tenantClaim(login)).contains(invitation.tenant().toString()).contains("\"member\"");
    }

    @Test
    @DisplayName("a grant left behind by a failure is adopted by the retry: one grant, and the subject is the invitation's")
    void failureAfterGrantIsAdoptedByTheRetry() throws Exception {
        Issued invitation = issue("member");
        UUID subject = InvitationHandlers.subjectOf(invitation.invitationId());
        String password = password();
        service.directory.failNextAfterGrant();

        TestExchange failed = accept(invitation, password);

        assertThat(failed.code()).isEqualTo(500);
        assertThat(grantsFor(subject)).hasSize(1);
        assertThat(credentials(invitation.email())).as("the account was rolled back").isZero();
        assertThat(pending(invitation)).isEqualTo(1);

        assertThat(accept(invitation, password).code()).isEqualTo(201);

        assertThat(service.directory.memberships(subject)).hasSize(1);
        assertThat(grantsFor(subject)).allSatisfy(g -> {
            assertThat(g.tenantId()).isEqualTo(invitation.tenant());
            assertThat(g.role()).isEqualTo("member");
        });
        TestExchange login = service.post(BASE + "/login", Map.of("email", invitation.email(), "password", password));
        assertThat(login.code()).isEqualTo(200);
        String claims = new String(Base64.getUrlDecoder().decode(
                json(login).get("accessToken").stringValue().split("\\.")[1]));
        assertThat(claims).contains("\"sub\":\"" + subject + "\"");
    }

    @Test
    @DisplayName("eight accepts of one token at once: one succeeds, seven are told the invitation is spent, one account exists")
    void concurrentAcceptsOfOneToken() throws Exception {
        Issued invitation = issue("member");
        int callers = 8;
        List<String> passwords = new ArrayList<>();
        for (int i = 0; i < callers; i++) {
            passwords.add(password());
        }
        String winner = null;
        CountDownLatch go = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(callers);
        try {
            List<Future<TestExchange>> results = new ArrayList<>();
            for (String password : passwords) {
                results.add(pool.submit(() -> {
                    go.await();
                    return accept(invitation, password);
                }));
            }
            go.countDown();
            int created = 0;
            int spent = 0;
            for (int i = 0; i < callers; i++) {
                TestExchange exchange = results.get(i).get();
                if (exchange.code() == 201) {
                    created++;
                    winner = passwords.get(i);
                } else {
                    assertThat(exchange.code()).isEqualTo(400);
                    assertThat(exchange.body()).isEqualTo(INVALID_INVITATION);
                    spent++;
                }
            }
            assertThat(created).isEqualTo(1);
            assertThat(spent).isEqualTo(callers - 1);
        } finally {
            pool.shutdownNow();
        }

        assertThat(credentials(invitation.email())).isEqualTo(1);
        assertThat(grantsFor(InvitationHandlers.subjectOf(invitation.invitationId()))).hasSize(1);
        String signedWith = winner;
        assertThat(service.post(BASE + "/login", Map.of("email", invitation.email(), "password", signedWith)).code())
                .as("the winning password signs in").isEqualTo(200);
        String loser = passwords.stream().filter(p -> !p.equals(signedWith)).findFirst().orElseThrow();
        assertThat(service.post(BASE + "/login", Map.of("email", invitation.email(), "password", loser)).code())
                .as("a losing password does not").isEqualTo(401);
    }

    @Test
    @DisplayName("an invitation that has expired creates nothing")
    void expiredInvitationCreatesNothing() throws Exception {
        Issued invitation = issue("member");
        try (Connection owner = service.database.owner();
             PreparedStatement age = owner.prepareStatement("UPDATE invitations SET created_at = now() - interval "
                     + "'2 days', expires_at = now() - interval '1 day' WHERE id = ?::uuid")) {
            age.setString(1, invitation.invitationId().toString());
            assertThat(age.executeUpdate()).isEqualTo(1);
        }

        TestExchange expired = accept(invitation, password());

        assertThat(expired.code()).isEqualTo(400);
        assertThat(expired.body()).isEqualTo(INVALID_INVITATION);
        assertThat(credentials(invitation.email())).isZero();
        assertThat(grantsFor(InvitationHandlers.subjectOf(invitation.invitationId()))).isEmpty();
    }

    @Test
    @DisplayName("repeating a successful accept answers that the invitation is spent, never that the account exists")
    void retryAfterSuccessIsInvalidInvitationNotAccountExists() {
        Issued invitation = issue("member");
        String password = password();
        assertThat(accept(invitation, password).code()).isEqualTo(201);

        TestExchange again = accept(invitation, password);

        assertThat(again.code()).isEqualTo(400);
        assertThat(again.body()).isEqualTo(INVALID_INVITATION);
    }

    @Test
    @DisplayName("an address that already has an account is refused, and the invitation it did not spend stays pending")
    void existingAccountKeepsTheInvitationPending() throws Exception {
        UUID tenant = UUID.randomUUID();
        String admin = service.accessToken(service.member(tenant, "admin"));
        IdentityHarness.Account existing = service.account();
        TestExchange issued = service.post(BASE + "/invitations",
                Map.of("email", existing.email(), "role", "member"), bearer(admin));
        JsonNode body = json(issued);
        Issued invitation = new Issued(tenant, UUID.fromString(body.get("invitationId").stringValue()),
                existing.email(), service.invitations.tokenFor(existing.email()));

        TestExchange taken = accept(invitation, password());

        assertThat(taken.code()).isEqualTo(409);
        assertThat(taken.body()).isEqualTo("{\"error\":\"account_exists\"}");
        assertThat(pending(invitation)).as("the consume was rolled back with the failed account").isEqualTo(1);
        assertThat(grantsFor(InvitationHandlers.subjectOf(invitation.invitationId()))).isEmpty();
        assertThat(credentials(existing.email())).isEqualTo(1);
    }
}
