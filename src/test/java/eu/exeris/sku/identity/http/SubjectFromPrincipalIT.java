package eu.exeris.sku.identity.http;

import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpMethod;
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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static eu.exeris.sku.identity.support.IdentityHarness.bearer;
import static eu.exeris.sku.identity.support.IdentityHarness.json;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The subject and the tenant of an authenticated call are the token's. A request that tries to name another
 * is refused, and a caller never reaches what belongs to another subject or tenant.
 */
@DisplayName("Subject and tenant come from the principal")
class SubjectFromPrincipalIT {

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

    @Test
    @DisplayName("a subject or tenant field in the body is refused on every route that reads a body")
    void bodyFieldsAreRefused() {
        UUID tenant = UUID.randomUUID();
        Account admin = service.member(tenant, "admin");
        Account victim = service.account();
        String token = service.accessToken(admin);
        Map<String, Map<String, Object>> bodies = new LinkedHashMap<>();
        bodies.put(BASE + "/password/change", Map.of("currentPassword", admin.password(),
                "newPassword", new String(TestConfig.randomPassword())));
        bodies.put(BASE + "/mfa/totp/enrollment", Map.of());
        bodies.put(BASE + "/mfa/totp/enrollment/confirm", Map.of("code", "123456"));
        bodies.put(BASE + "/mfa/recovery-codes", Map.of());
        bodies.put(BASE + "/sessions/revoke", Map.of("sessionId", UUID.randomUUID().toString()));
        bodies.put(BASE + "/invitations", Map.of("email", "new@example.test", "role", "member"));

        for (Map.Entry<String, Map<String, Object>> route : bodies.entrySet()) {
            for (String field : List.of("subjectId", "tenantId", "actorId", "sub", "tid")) {
                Map<String, Object> body = new LinkedHashMap<>(route.getValue());
                body.put(field, victim.subject().toString());

                TestExchange exchange = service.post(route.getKey(), body, bearer(token));

                assertThat(exchange.code()).as(route.getKey() + " with " + field).isEqualTo(400);
                assertThat(exchange.body()).isEqualTo("{\"error\":\"invalid_request\"}");
            }
        }
    }

    @Test
    @DisplayName("a body on a route that takes none, or a query string, is refused")
    void unexpectedInputIsRefused() {
        String token = service.accessToken(service.account());
        UUID victim = UUID.randomUUID();

        TestExchange withBody = service.post(BASE + "/sessions/revoke-all", Map.of("subjectId", victim.toString()),
                bearer(token));
        TestExchange listWithQuery = service.send(HttpMethod.GET, BASE + "/sessions?subjectId=" + victim,
                bearer(token));
        TestExchange revokeAllWithQuery = service.send(HttpMethod.POST, BASE + "/sessions/revoke-all?subjectId=" + victim,
                bearer(token));

        assertThat(withBody.code()).isEqualTo(400);
        assertThat(listWithQuery.code()).isIn(400, 404);
        assertThat(revokeAllWithQuery.code()).isIn(400, 404);
        assertThat(listWithQuery.body()).doesNotContain(victim.toString());
    }

    @Test
    @DisplayName("a caller lists only the sessions of its own subject")
    void listIsOwn() {
        Account alice = service.account();
        Account bob = service.account();
        JsonNode aliceLogin = service.login(alice);
        String bobToken = service.accessToken(bob);

        TestExchange list = service.send(HttpMethod.GET, BASE + "/sessions", bearer(bobToken));

        assertThat(list.code()).isEqualTo(200);
        assertThat(list.body()).doesNotContain(aliceLogin.get("sessionId").stringValue());
        assertThat(json(list).get("sessions").size()).isEqualTo(1);
    }

    @Test
    @DisplayName("revoking another subject's session is indistinguishable from revoking none, and changes nothing")
    void foreignSessionCannotBeRevoked() {
        Account alice = service.account();
        Account bob = service.account();
        JsonNode aliceLogin = service.login(alice);
        String aliceToken = aliceLogin.get("accessToken").stringValue();
        String bobToken = service.accessToken(bob);

        TestExchange foreign = service.post(BASE + "/sessions/revoke",
                Map.of("sessionId", aliceLogin.get("sessionId").stringValue()), bearer(bobToken));
        TestExchange unknown = service.post(BASE + "/sessions/revoke",
                Map.of("sessionId", UUID.randomUUID().toString()), bearer(bobToken));

        assertThat(foreign.code()).isEqualTo(404);
        assertThat(foreign.body()).isEqualTo(unknown.body());
        TestExchange stillThere = service.send(HttpMethod.GET, BASE + "/sessions", bearer(aliceToken));
        assertThat(stillThere.body()).contains(aliceLogin.get("sessionId").stringValue());
    }

    @Test
    @DisplayName("revoking every session ends the caller's sessions and leaves other subjects' alone")
    void revokeAllIsOwn() {
        Account alice = service.account();
        Account bob = service.account();
        JsonNode aliceLogin = service.login(alice);
        String bobToken = service.accessToken(bob);

        TestExchange exchange = service.send(HttpMethod.POST, BASE + "/sessions/revoke-all", bearer(bobToken));

        assertThat(exchange.code()).isEqualTo(200);
        TestExchange refreshed = service.post(BASE + "/refresh",
                Map.of("refreshToken", aliceLogin.get("refreshToken").stringValue()));
        assertThat(refreshed.code()).isEqualTo(200);
    }

    @Test
    @DisplayName("a password change changes the caller's password and nobody else's")
    void passwordChangeIsOwn() {
        Account alice = service.account();
        Account bob = service.account();
        String bobToken = service.accessToken(bob);
        String bobOtherToken = service.accessToken(bob);
        String replacement = new String(TestConfig.randomPassword());

        TestExchange changed = service.post(BASE + "/password/change",
                Map.of("currentPassword", bob.password(), "newPassword", replacement), bearer(bobToken));
        TestExchange usingAlicesPassword = service.post(BASE + "/password/change",
                Map.of("currentPassword", alice.password(), "newPassword", replacement),
                bearer(bobOtherToken));

        assertThat(changed.code()).isEqualTo(204);
        assertThat(usingAlicesPassword.code()).as("the password of another subject proves nothing").isEqualTo(403);
        assertThat(service.post(BASE + "/login", IdentityHarness.credentials(alice)).code()).isEqualTo(200);
    }

    @Test
    @DisplayName("an invitation is issued into the token's tenant, and a token of another tenant's admin cannot reach this one")
    void invitationTenantIsTheTokens() {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();
        String adminB = service.accessToken(service.member(tenantB, "admin"));
        String email = "invitee-" + UUID.randomUUID().toString().substring(0, 8) + "@example.test";

        TestExchange issued = service.post(BASE + "/invitations", Map.of("email", email, "role", "member"),
                bearer(adminB));

        assertThat(issued.code()).isEqualTo(201);
        JsonNode body = json(issued);
        assertThat(body.get("tenantId").stringValue()).isEqualTo(tenantB.toString());
        String token = service.invitations.tokenFor(email);
        assertThat(TenantScope.call(tenantB,
                () -> service.composition.services().invitations().findPending(token, tenantB, email))).isPresent();
        assertThat(TenantScope.call(tenantA,
                () -> service.composition.services().invitations().findPending(token, tenantA, email))).isEmpty();
        assertThat(TenantScope.call(tenantB,
                () -> service.composition.services().invitations().findPending(token, tenantA, email))).isEmpty();
    }

    @Test
    @DisplayName("a token that names no tenant cannot issue invitations")
    void tenantlessTokenCannotInvite() {
        Account both = service.member(UUID.randomUUID(), "admin");
        service.directory.grant(UUID.randomUUID(), both.subject(), "admin");
        String token = service.accessToken(both);

        TestExchange exchange = service.post(BASE + "/invitations",
                Map.of("email", "new@example.test", "role", "member"), bearer(token));

        assertThat(exchange.code()).isEqualTo(403);
    }

    @Test
    @DisplayName("a token whose holder lost the role since it was issued cannot issue invitations")
    void staleScopeIsRecheckedAgainstTheDirectory() {
        UUID tenant = UUID.randomUUID();
        Account admin = service.member(tenant, "admin");
        String token = service.accessToken(admin);
        service.directory.grant(tenant, admin.subject(), "member");

        TestExchange exchange = service.post(BASE + "/invitations",
                Map.of("email", "new@example.test", "role", "member"), bearer(token));

        assertThat(exchange.code()).isEqualTo(403);
        assertThat(exchange.body()).isEqualTo("{\"error\":\"forbidden\"}");
    }

    @Test
    @DisplayName("a header cannot stand in for the token's subject")
    void headersDoNotNameASubject() {
        Account alice = service.account();
        Account bob = service.account();
        JsonNode aliceLogin = service.login(alice);
        String bobToken = service.accessToken(bob);

        TestExchange exchange = service.send(HttpMethod.GET, BASE + "/sessions", bearer(bobToken),
                new HttpHeader("X-Subject-Id", alice.subject().toString()),
                new HttpHeader("X-Tenant-Id", UUID.randomUUID().toString()));

        assertThat(exchange.code()).isEqualTo(200);
        assertThat(exchange.body()).doesNotContain(aliceLogin.get("sessionId").stringValue());
    }
}
