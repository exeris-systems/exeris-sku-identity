package eu.exeris.sku.identity.http;

import eu.exeris.sku.identity.support.IdentityHarness;
import eu.exeris.sku.identity.support.TestConfig;
import eu.exeris.sku.identity.support.TestExchange;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Mailbox verification")
class VerificationIT {

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
    @DisplayName("an unverified account is verified with the token sent to its address, and can then sign in")
    void verification() {
        UUID subject = UUID.randomUUID();
        String email = "pending-" + UUID.randomUUID().toString().substring(0, 10) + "@example.test";
        String password = new String(TestConfig.randomPassword());
        service.composition.services().credentialStore().createCredential(subject, email, password.toCharArray());
        assertThat(service.post(BASE + "/login", Map.of("email", email, "password", password)).code())
                .isEqualTo(403);

        TestExchange sent = service.post(BASE + "/verification/send", Map.of("email", email));
        String token = service.notifications.verifications().stream()
                .filter(v -> v.subjectId().equals(subject)).findFirst().orElseThrow().token();
        TestExchange verified = service.post(BASE + "/verification/verify", Map.of("token", token));
        TestExchange replay = service.post(BASE + "/verification/verify", Map.of("token", token));

        assertThat(sent.code()).isEqualTo(202);
        assertThat(verified.code()).isEqualTo(200);
        assertThat(verified.body()).isEqualTo("{\"verified\":true}");
        assertThat(replay.code()).isEqualTo(400);
        assertThat(replay.body()).isEqualTo("{\"error\":\"invalid_token\"}");
        assertThat(service.post(BASE + "/login", Map.of("email", email, "password", password)).code())
                .isEqualTo(200);
    }

    @Test
    @DisplayName("a request for an unknown or an already verified address answers like any other and sends nothing")
    void sendIsUniform() {
        IdentityHarness.Account verified = service.account();
        int before = service.notifications.verifications().size();

        TestExchange known = service.post(BASE + "/verification/send", Map.of("email", verified.email()));
        TestExchange unknown = service.post(BASE + "/verification/send",
                Map.of("email", "nobody-" + UUID.randomUUID() + "@example.test"));

        assertThat(known.code()).isEqualTo(202);
        assertThat(known.body()).isEqualTo(unknown.body());
        assertThat(service.notifications.verifications()).hasSize(before);
    }

    @Test
    @DisplayName("an unknown token verifies nothing")
    void unknownToken() {
        TestExchange exchange = service.post(BASE + "/verification/verify",
                Map.of("token", "unknown-" + UUID.randomUUID()));

        assertThat(exchange.code()).isEqualTo(400);
        assertThat(exchange.body()).isEqualTo("{\"error\":\"invalid_token\"}");
    }
}
