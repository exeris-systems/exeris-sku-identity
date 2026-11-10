package eu.exeris.sku.identity.http;

import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.sku.identity.support.IdentityHarness;
import eu.exeris.sku.identity.support.TestExchange;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Cross-origin access")
class CorsIT {

    private static final String ALLOWED = "https://app.example.test";
    private static final String LOGIN = "/api/v1/auth/login";

    private static TestExchange preflight(IdentityHarness service, String origin, String method) {
        return service.send(HttpMethod.OPTIONS, LOGIN,
                new HttpHeader("Origin", origin),
                new HttpHeader("Access-Control-Request-Method", method),
                new HttpHeader("Access-Control-Request-Headers", "content-type"));
    }

    @Test
    @DisplayName("with no origin configured there are no preflight routes and no CORS header")
    void offByDefault() throws Exception {
        try (IdentityHarness service = IdentityHarness.start()) {
            TestExchange preflight = preflight(service, ALLOWED, "POST");
            TestExchange actual = service.post(LOGIN, Map.of("email", "a@example.test", "password", "x"),
                    new HttpHeader("Origin", ALLOWED));

            assertThat(preflight.code()).isIn(404, 405);
            assertThat(preflight.header("Access-Control-Allow-Origin")).isNull();
            assertThat(actual.header("Access-Control-Allow-Origin")).isNull();
        }
    }

    @Test
    @DisplayName("a configured origin gets a preflight answer and CORS headers on responses; another origin gets none")
    void configuredOrigin() throws Exception {
        try (IdentityHarness service = IdentityHarness.start(Map.of("EXERIS_CORS_ALLOWED_ORIGINS", ALLOWED))) {
            TestExchange allowed = preflight(service, ALLOWED, "POST");
            TestExchange denied = preflight(service, "https://evil.example.test", "POST");
            TestExchange deniedMethod = preflight(service, ALLOWED, "DELETE");
            TestExchange actual = service.post(LOGIN, Map.of("email", "a@example.test", "password", "x"),
                    new HttpHeader("Origin", ALLOWED));
            TestExchange foreign = service.post(LOGIN, Map.of("email", "a@example.test", "password", "x"),
                    new HttpHeader("Origin", "https://evil.example.test"));

            assertThat(allowed.code()).isEqualTo(204);
            assertThat(allowed.header("Access-Control-Allow-Origin")).isEqualTo(ALLOWED);
            assertThat(allowed.header("Access-Control-Allow-Credentials")).isNull();
            assertThat(denied.code()).isEqualTo(403);
            assertThat(denied.header("Access-Control-Allow-Origin")).isNull();
            assertThat(deniedMethod.code()).isEqualTo(403);
            assertThat(actual.code()).isEqualTo(401);
            assertThat(actual.header("Access-Control-Allow-Origin")).isEqualTo(ALLOWED);
            assertThat(foreign.header("Access-Control-Allow-Origin")).isNull();
        }
    }

    @Test
    @DisplayName("a preflight reaches no handler and needs no token, even for a private route")
    void preflightOfPrivateRoute() throws Exception {
        try (IdentityHarness service = IdentityHarness.start(Map.of("EXERIS_CORS_ALLOWED_ORIGINS", ALLOWED))) {
            TestExchange exchange = service.send(HttpMethod.OPTIONS, "/api/v1/auth/sessions",
                    new HttpHeader("Origin", ALLOWED), new HttpHeader("Access-Control-Request-Method", "GET"));

            assertThat(exchange.code()).isEqualTo(204);
        }
    }
}
