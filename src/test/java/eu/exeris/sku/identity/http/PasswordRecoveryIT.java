package eu.exeris.sku.identity.http;

import eu.exeris.sku.identity.support.IdentityHarness;
import eu.exeris.sku.identity.support.IdentityHarness.Account;
import eu.exeris.sku.identity.support.RecordingNotificationDispatcher.Sent;
import eu.exeris.sku.identity.support.TestConfig;
import eu.exeris.sku.identity.support.TestExchange;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

import java.util.Map;
import java.util.UUID;

import static eu.exeris.sku.identity.support.IdentityHarness.bearer;
import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Password change and recovery")
class PasswordRecoveryIT {

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

    private static String resetTokenFor(Account account) {
        assertThat(service.post(BASE + "/password/reset-request", Map.of("email", account.email())).code())
                .isEqualTo(202);
        return service.notifications.resets().stream()
                .filter(sent -> sent.subjectId().equals(account.subject()))
                .reduce((first, second) -> second).map(Sent::token).orElseThrow();
    }

    @Test
    @DisplayName("a reset request answers the same for a known and an unknown address, and sends only to the known")
    void requestIsUniform() {
        Account account = service.account();
        int before = service.notifications.resets().size();

        TestExchange known = service.post(BASE + "/password/reset-request", Map.of("email", account.email()));
        TestExchange unknown = service.post(BASE + "/password/reset-request",
                Map.of("email", "nobody-" + UUID.randomUUID() + "@example.test"));

        assertThat(known.code()).isEqualTo(202);
        assertThat(unknown.code()).isEqualTo(202);
        assertThat(known.body()).isEqualTo(unknown.body());
        assertThat(service.notifications.resets()).hasSize(before + 1);
        assertThat(service.notifications.resets().get(before).recipient()).isEqualToIgnoringCase(account.email());
    }

    @Test
    @DisplayName("a reset token sets the password once, ends the sessions and signs in with the new password")
    void reset() {
        Account account = service.account();
        JsonNode session = service.login(account);
        String token = resetTokenFor(account);
        String replacement = new String(TestConfig.randomPassword());

        TestExchange done = service.post(BASE + "/password/reset", Map.of("token", token, "newPassword", replacement));
        TestExchange replay = service.post(BASE + "/password/reset",
                Map.of("token", token, "newPassword", new String(TestConfig.randomPassword())));

        assertThat(done.code()).isEqualTo(204);
        assertThat(replay.code()).isEqualTo(400);
        assertThat(replay.body()).isEqualTo("{\"error\":\"invalid_token\"}");
        assertThat(service.post(BASE + "/login", IdentityHarness.credentials(account)).code()).isEqualTo(401);
        assertThat(service.post(BASE + "/login", Map.of("email", account.email(), "password", replacement)).code())
                .isEqualTo(200);
        assertThat(service.post(BASE + "/refresh", Map.of("refreshToken", session.get("refreshToken").stringValue()))
                .code()).as("sessions end with the reset").isEqualTo(401);
    }

    @Test
    @DisplayName("a reset to the current password, or to one the policy refuses, is refused and keeps the token usable")
    void refusedResetKeepsTheToken() {
        Account account = service.account();
        String token = resetTokenFor(account);

        TestExchange same = service.post(BASE + "/password/reset", Map.of("token", token, "newPassword", account.password()));
        TestExchange weak = service.post(BASE + "/password/reset", Map.of("token", token, "newPassword", "x"));
        TestExchange fine = service.post(BASE + "/password/reset",
                Map.of("token", token, "newPassword", new String(TestConfig.randomPassword())));

        assertThat(same.code()).isEqualTo(400);
        assertThat(same.body()).isEqualTo("{\"error\":\"same_password\"}");
        assertThat(weak.code()).isEqualTo(400);
        assertThat(weak.body()).isEqualTo("{\"error\":\"invalid_password\"}");
        assertThat(fine.code()).isEqualTo(204);
    }

    @Test
    @DisplayName("an unknown reset token is refused")
    void unknownToken() {
        TestExchange exchange = service.post(BASE + "/password/reset",
                Map.of("token", "unknown-" + UUID.randomUUID(), "newPassword", new String(TestConfig.randomPassword())));

        assertThat(exchange.code()).isEqualTo(400);
        assertThat(exchange.body()).isEqualTo("{\"error\":\"invalid_token\"}");
    }

    @Test
    @DisplayName("a signed-in caller changes the password with the current one; that ends their sessions")
    void change() {
        Account account = service.account();
        JsonNode session = service.login(account);
        String access = session.get("accessToken").stringValue();
        String replacement = new String(TestConfig.randomPassword());

        TestExchange wrong = service.post(BASE + "/password/change",
                Map.of("currentPassword", new String(TestConfig.randomPassword()), "newPassword", replacement),
                bearer(access));
        TestExchange same = service.post(BASE + "/password/change",
                Map.of("currentPassword", account.password(), "newPassword", account.password()), bearer(access));
        TestExchange done = service.post(BASE + "/password/change",
                Map.of("currentPassword", account.password(), "newPassword", replacement), bearer(access));

        assertThat(wrong.code()).isEqualTo(403);
        assertThat(wrong.body()).isEqualTo("{\"error\":\"wrong_password\"}");
        assertThat(same.code()).isEqualTo(400);
        assertThat(done.code()).isEqualTo(204);
        assertThat(service.post(BASE + "/login", Map.of("email", account.email(), "password", replacement)).code())
                .isEqualTo(200);
        assertThat(service.post(BASE + "/refresh", Map.of("refreshToken", session.get("refreshToken").stringValue()))
                .code()).isEqualTo(401);
    }
}
