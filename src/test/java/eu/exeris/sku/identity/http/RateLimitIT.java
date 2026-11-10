package eu.exeris.sku.identity.http;

import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.sku.identity.support.IdentityHarness;
import eu.exeris.sku.identity.support.TestExchange;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Rate limiting of the public credential routes")
class RateLimitIT {

    @Test
    @DisplayName("a client that exceeds the limit is refused with 429 while another client is not")
    void limitIsPerClient() throws Exception {
        try (IdentityHarness service = IdentityHarness.start(Map.of("EXERIS_RATELIMIT_LOGIN_CAPACITY", "3"))) {
            Map<String, Object> body = Map.of("email", "a@example.test", "password", "x");
            int refused = 0;
            for (int i = 0; i < 6; i++) {
                TestExchange exchange = service.send(
                        TestExchange.json(
                                HttpMethod.POST, "/api/v1/auth/login",
                                IdentityHarness.write(body)).from("203.0.113.10"));
                if (exchange.code() == 429) {
                    refused++;
                } else {
                    assertThat(exchange.code()).isEqualTo(401);
                }
            }
            TestExchange other = service.send(TestExchange.json(HttpMethod.POST,
                    "/api/v1/auth/login", IdentityHarness.write(body)).from("203.0.113.11"));

            assertThat(refused).isEqualTo(3);
            assertThat(other.code()).isEqualTo(401);
        }
    }

    @Test
    @DisplayName("the second-factor route shares the login group's limit")
    void mfaVerifyIsLimited() throws Exception {
        try (IdentityHarness service = IdentityHarness.start(Map.of("EXERIS_RATELIMIT_LOGIN_CAPACITY", "2"))) {
            Map<String, Object> body = Map.of("challengeToken", "unknown", "code", "123456");
            int last = 0;
            for (int i = 0; i < 4; i++) {
                last = service.send(TestExchange.json(HttpMethod.POST,
                        "/api/v1/auth/mfa/verify", IdentityHarness.write(body)).from("203.0.113.20")).code();
            }

            assertThat(last).isEqualTo(429);
        }
    }
}
