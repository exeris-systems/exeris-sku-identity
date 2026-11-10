package eu.exeris.sku.identity.http;

import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.sku.identity.support.IdentityHarness;
import eu.exeris.sku.identity.support.IdentityHarness.Account;
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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Password authentication")
class PasswordAuthenticationIT {

    private static IdentityHarness service;

    @BeforeAll
    static void start() throws Exception {
        service = IdentityHarness.start();
    }

    @AfterAll
    static void stop() {
        service.close();
    }

    private static final String LOGIN = "/api/v1/auth/login";

    private static Map<String, Object> body(String email, String password) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("email", email);
        body.put("password", password);
        return body;
    }

    @Test
    @DisplayName("a correct password opens a session and returns a bearer token, a refresh token and the session")
    void loginSucceeds() {
        Account account = service.account();

        TestExchange exchange = service.post(LOGIN, IdentityHarness.credentials(account));

        assertThat(exchange.code()).isEqualTo(200);
        assertThat(exchange.header("Cache-Control")).isEqualTo("no-store");
        JsonNode tokens = IdentityHarness.json(exchange);
        assertThat(tokens.get("tokenType").stringValue()).isEqualToIgnoringCase("Bearer");
        assertThat(tokens.get("accessToken").stringValue()).isNotBlank();
        assertThat(tokens.get("refreshToken").stringValue()).isNotBlank();
        assertThat(tokens.has("mfaRequired")).isFalse();
        TestExchange sessions = service.send(HttpMethod.GET, "/api/v1/auth/sessions",
                IdentityHarness.bearer(tokens.get("accessToken").stringValue()));
        assertThat(sessions.code()).isEqualTo(200);
        assertThat(sessions.body()).contains(tokens.get("sessionId").stringValue());
    }

    @Test
    @DisplayName("the login is not case sensitive")
    void loginIgnoresCase() {
        Account account = service.account();

        TestExchange exchange = service.post(LOGIN, body(account.email().toUpperCase(), account.password()));

        assertThat(exchange.code()).isEqualTo(200);
    }

    @Test
    @DisplayName("a wrong password and an unknown login are refused with the same answer")
    void wrongPasswordAndUnknownLoginAreAlike() {
        Account account = service.account();

        TestExchange wrong = service.post(LOGIN, body(account.email(), new String(TestConfig.randomPassword())));
        TestExchange unknown = service.post(LOGIN,
                body("nobody-" + UUID.randomUUID() + "@example.test", new String(TestConfig.randomPassword())));

        assertThat(wrong.code()).isEqualTo(401);
        assertThat(unknown.code()).isEqualTo(401);
        assertThat(wrong.body()).isEqualTo(unknown.body()).isEqualTo("{\"error\":\"invalid_credentials\"}");
    }

    @Test
    @DisplayName("repeated failures lock the account, and a locked account is refused like a wrong password")
    void lockout() {
        Account account = service.account();
        int attempts = service.config.credentials().lockout().maxAttempts();

        for (int i = 0; i < attempts; i++) {
            assertThat(service.post(LOGIN, body(account.email(), new String(TestConfig.randomPassword()))).code())
                    .isEqualTo(401);
        }
        TestExchange locked = service.post(LOGIN, IdentityHarness.credentials(account));

        assertThat(locked.code()).isEqualTo(401);
        assertThat(locked.body()).isEqualTo("{\"error\":\"invalid_credentials\"}");
    }

    @Test
    @DisplayName("a correct password on an unverified mailbox is told so, and a wrong one is not")
    void unverified() {
        UUID subject = UUID.randomUUID();
        String email = "pending-" + UUID.randomUUID().toString().substring(0, 12) + "@example.test";
        String password = new String(TestConfig.randomPassword());
        service.composition.services().credentialStore().createCredential(subject, email, password.toCharArray());

        TestExchange right = service.post(LOGIN, body(email, password));
        TestExchange wrong = service.post(LOGIN, body(email, new String(TestConfig.randomPassword())));

        assertThat(right.code()).isEqualTo(403);
        assertThat(right.body()).isEqualTo("{\"error\":\"account_unverified\"}");
        assertThat(wrong.body()).isEqualTo("{\"error\":\"invalid_credentials\"}");
    }

    @Test
    @DisplayName("a hash made under older parameters is replaced by one under the configured parameters")
    void rehashAfterConfigurationChange() throws Exception {
        Account account;
        String before;
        try (IdentityHarness first = IdentityHarness.start(Map.of())) {
            account = first.account();
            before = storedHash(first, account.subject());
            assertThat(first.post(LOGIN, IdentityHarness.credentials(account)).code()).isEqualTo(200);
            assertThat(storedHash(first, account.subject())).isEqualTo(before);
            try (IdentityHarness second = first.restartedWith(
                    Map.of("EXERIS_PASSWORD_ARGON2_ITERATIONS", "4"))) {
                TestExchange exchange = second.post(LOGIN, IdentityHarness.credentials(account));

                assertThat(exchange.code()).isEqualTo(200);
                String after = storedHash(second, account.subject());
                assertThat(after).isNotEqualTo(before).contains("t=4");
                assertThat(second.post(LOGIN, IdentityHarness.credentials(account)).code()).isEqualTo(200);
            }
        }
    }

    private static String storedHash(IdentityHarness harness, UUID subject) throws Exception {
        try (Connection owner = harness.database.owner();
             PreparedStatement statement = owner.prepareStatement(
                     "SELECT password_hash FROM credential_records WHERE subject_id = ?")) {
            statement.setObject(1, subject);
            try (ResultSet rows = statement.executeQuery()) {
                rows.next();
                return rows.getString(1);
            }
        }
    }
}
