package eu.exeris.sku.identity.http;

import eu.exeris.sku.identity.auth.TenantScope;
import eu.exeris.sku.identity.support.IdentityHarness;
import eu.exeris.sku.identity.support.IdentityHarness.Account;
import eu.exeris.sku.identity.support.TestConfig;
import eu.exeris.sku.identity.support.TestExchange;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import static eu.exeris.sku.identity.support.IdentityHarness.bearer;
import static eu.exeris.sku.identity.support.IdentityHarness.json;
import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Invitation onboarding")
class InvitationOnboardingIT {

    private static final String BASE = "/api/v1/auth";

    private static IdentityHarness service;

    @BeforeAll
    static void start() throws Exception {
        service = IdentityHarness.start();
    }

    @AfterAll
    static void stop() {
        service.close();
    }

    private static String email() {
        return "invitee-" + UUID.randomUUID().toString().substring(0, 10) + "@example.test";
    }

    private static TestExchange invite(String token, String email, String role) {
        return service.post(BASE + "/invitations", Map.of("email", email, "role", role), bearer(token));
    }

    private static Map<String, Object> accept(UUID tenant, String token, String email, String password) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("tenantId", tenant.toString());
        body.put("token", token);
        body.put("email", email);
        body.put("password", password);
        return body;
    }

    private static boolean pending(UUID tenant, String token, String email) {
        return TenantScope.call(tenant,
                () -> service.composition.services().invitations().findPending(token, tenant, email).isPresent());
    }

    @Test
    @DisplayName("an admin invites, and the invitee accepts, gets an account and signs in to the inviting tenant")
    void fullFlow() {
        UUID tenant = UUID.randomUUID();
        String admin = service.accessToken(service.member(tenant, "admin"));
        String email = email();
        TestExchange issued = invite(admin, email, "member");
        assertThat(issued.code()).isEqualTo(201);
        String token = service.invitations.tokenFor(email);
        String password = new String(TestConfig.randomPassword());

        TestExchange accepted = service.post(BASE + "/invitations/accept", accept(tenant, token, email, password));

        assertThat(accepted.code()).isEqualTo(201);
        assertThat(json(accepted).get("tenantId").stringValue()).isEqualTo(tenant.toString());
        assertThat(json(accepted).get("role").stringValue()).isEqualTo("member");
        JsonNode login = json(service.post(BASE + "/login", Map.of("email", email, "password", password)));
        String claims = new String(Base64.getUrlDecoder().decode(
                login.get("accessToken").stringValue().split("\\.")[1]));
        assertThat(claims).contains(tenant.toString()).contains("\"member\"");
        assertThat(pending(tenant, token, email)).isFalse();
    }

    @Test
    @DisplayName("an invitation can be accepted once")
    void singleUse() {
        UUID tenant = UUID.randomUUID();
        String admin = service.accessToken(service.member(tenant, "owner"));
        String email = email();
        String token = service.invite(admin, email, "member");
        assertThat(service.post(BASE + "/invitations/accept",
                accept(tenant, token, email, new String(TestConfig.randomPassword()))).code()).isEqualTo(201);

        TestExchange again = service.post(BASE + "/invitations/accept",
                accept(tenant, token, email, new String(TestConfig.randomPassword())));

        assertThat(again.code()).isEqualTo(400);
        assertThat(again.body()).isEqualTo("{\"error\":\"invalid_invitation\"}");
    }

    @Test
    @DisplayName("the tenant of the membership is the invitation's: another tenant, or another address, opens nothing")
    void wrongTenantOrAddress() {
        UUID tenant = UUID.randomUUID();
        UUID other = UUID.randomUUID();
        String admin = service.accessToken(service.member(tenant, "admin"));
        String email = email();
        String token = service.invite(admin, email, "member");
        String password = new String(TestConfig.randomPassword());

        TestExchange foreignTenant = service.post(BASE + "/invitations/accept", accept(other, token, email, password));
        String stranger = email();
        TestExchange foreignAddress = service.post(BASE + "/invitations/accept",
                accept(tenant, token, stranger, password));

        assertThat(foreignTenant.body()).isEqualTo("{\"error\":\"invalid_invitation\"}");
        assertThat(foreignAddress.body()).isEqualTo("{\"error\":\"invalid_invitation\"}");
        assertThat(service.post(BASE + "/login", Map.of("email", stranger, "password", password)).code())
                .as("no account was created").isEqualTo(401);
        assertThat(service.post(BASE + "/login", Map.of("email", email, "password", password)).code())
                .as("no account was created").isEqualTo(401);
        assertThat(pending(tenant, token, email)).isTrue();
        assertThat(service.post(BASE + "/invitations/accept", accept(tenant, token, email, password)).code())
                .isEqualTo(201);
    }

    @Test
    @DisplayName("a password the policy refuses, or an address that already has an account, leaves the invitation pending")
    void failedAcceptanceDoesNotSpendTheInvitation() {
        UUID tenant = UUID.randomUUID();
        String admin = service.accessToken(service.member(tenant, "admin"));
        String email = email();
        String token = service.invite(admin, email, "member");

        TestExchange weak = service.post(BASE + "/invitations/accept", accept(tenant, token, email, "x"));

        assertThat(weak.code()).isEqualTo(400);
        assertThat(weak.body()).isEqualTo("{\"error\":\"invalid_password\"}");
        assertThat(pending(tenant, token, email)).isTrue();

        Account existing = service.account();
        String takenToken = service.invite(admin, existing.email(), "member");
        TestExchange taken = service.post(BASE + "/invitations/accept",
                accept(tenant, takenToken, existing.email(), new String(TestConfig.randomPassword())));

        assertThat(taken.code()).isEqualTo(409);
        assertThat(taken.body()).isEqualTo("{\"error\":\"account_exists\"}");
        assertThat(pending(tenant, takenToken, existing.email())).isTrue();
    }

    @Test
    @DisplayName("a body that names a role or a subject is refused; the invitation decides both")
    void acceptTakesNoRoleOrSubject() {
        UUID tenant = UUID.randomUUID();
        String admin = service.accessToken(service.member(tenant, "admin"));
        String email = email();
        String token = service.invite(admin, email, "member");

        for (String field : new String[] {"role", "subjectId"}) {
            Map<String, Object> body = accept(tenant, token, email, new String(TestConfig.randomPassword()));
            body.put(field, "admin");

            assertThat(service.post(BASE + "/invitations/accept", body).code()).as(field).isEqualTo(400);
        }
        assertThat(pending(tenant, token, email)).isTrue();
    }

    @Test
    @DisplayName("issuing needs the scope: a member, and a caller without a token, are refused")
    void issuingNeedsTheScope() {
        UUID tenant = UUID.randomUUID();
        String member = service.accessToken(service.member(tenant, "member"));

        assertThat(invite(member, email(), "member").code()).isEqualTo(403);
        assertThat(service.post(BASE + "/invitations", Map.of("email", email(), "role", "member")).code())
                .isEqualTo(401);
    }

    @Test
    @DisplayName("the platform role is never granted by an invitation, and only an owner invites an owner")
    void roleLimits() {
        UUID tenant = UUID.randomUUID();
        String admin = service.accessToken(service.member(tenant, "admin"));
        String owner = service.accessToken(service.member(tenant, "owner"));

        assertThat(invite(admin, email(), "platform-admin").code()).isEqualTo(403);
        assertThat(invite(owner, email(), "platform-admin").code()).isEqualTo(403);
        assertThat(invite(admin, email(), "owner").code()).isEqualTo(403);
        assertThat(invite(admin, email(), "Not A Role").code()).isEqualTo(403);
        assertThat(invite(owner, email(), "owner").code()).isEqualTo(201);
        assertThat(invite(admin, email(), "admin").code()).isEqualTo(201);
    }

    @Test
    @DisplayName("with no invitation delivery, issuing is refused and stores nothing")
    void noDeliveryFailsClosed() throws Exception {
        try (IdentityHarness undelivered = IdentityHarness.start(Map.of(), false)) {
            UUID tenant = UUID.randomUUID();
            String admin = undelivered.accessToken(undelivered.member(tenant, "admin"));
            String email = email();

            TestExchange issued = undelivered.post(BASE + "/invitations",
                    Map.of("email", email, "role", "member"), bearer(admin));

            assertThat(issued.code()).isEqualTo(503);
            assertThat(issued.body()).isEqualTo("{\"error\":\"invitation_delivery_unavailable\"}");
            assertThat(invitationRows(undelivered, email)).isZero();
        }
    }

    @Test
    @DisplayName("a delivery that fails leaves no invitation behind")
    void deliveryFailureLeavesNoInvitation() throws Exception {
        UUID tenant = UUID.randomUUID();
        String admin = service.accessToken(service.member(tenant, "admin"));
        String email = email();
        service.invitations.failNext();

        TestExchange failed = invite(admin, email, "member");

        assertThat(failed.code()).isEqualTo(502);
        assertThat(failed.body()).isEqualTo("{\"error\":\"invitation_delivery_failed\"}");
        assertThat(invitationRows(service, email)).isZero();
        assertThat(invite(admin, email, "member").code()).as("the next attempt succeeds").isEqualTo(201);
        assertThat(invitationRows(service, email)).isEqualTo(1);
    }

    private static long invitationRows(IdentityHarness harness, String email) throws Exception {
        try (java.sql.Connection owner = harness.database.owner();
             java.sql.PreparedStatement count = owner.prepareStatement(
                     "SELECT count(*) FROM invitations WHERE email = ?")) {
            count.setString(1, email);
            try (java.sql.ResultSet rows = count.executeQuery()) {
                rows.next();
                return rows.getLong(1);
            }
        }
    }

    @Test
    @DisplayName("a lifetime beyond the maximum is refused")
    void lifetimeIsBounded() {
        UUID tenant = UUID.randomUUID();
        String admin = service.accessToken(service.member(tenant, "admin"));

        TestExchange tooLong = service.post(BASE + "/invitations",
                Map.of("email", email(), "role", "member", "ttlSeconds", 365L * 24 * 3600), bearer(admin));
        TestExchange short1 = service.post(BASE + "/invitations",
                Map.of("email", email(), "role", "member", "ttlSeconds", 3600), bearer(admin));

        assertThat(tooLong.code()).isEqualTo(400);
        assertThat(short1.code()).isEqualTo(201);
    }
}
