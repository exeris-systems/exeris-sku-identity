package eu.exeris.sku.identity.http;

import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.sku.identity.support.IdentityHarness;
import eu.exeris.sku.identity.support.TestExchange;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Request bodies")
class RequestBodyIT {

    private static final String LOGIN = "/api/v1/auth/login";
    private static final String INVALID = "{\"error\":\"invalid_request\"}";

    private static IdentityHarness service;

    @BeforeAll
    static void start() throws Exception {
        service = IdentityHarness.start();
    }

    @AfterAll
    static void stop() {
        service.close();
    }

    private static TestExchange post(String body) {
        return service.send(TestExchange.json(HttpMethod.POST, LOGIN, body));
    }

    @Test
    @DisplayName("a body that is not declared as JSON is refused with 415")
    void contentTypeIsRequired() {
        TestExchange exchange = service.send(TestExchange.withBody(HttpMethod.POST, LOGIN,
                "{\"email\":\"a@example.test\",\"password\":\"x\"}", "application/x-www-form-urlencoded"));

        assertThat(exchange.code()).isEqualTo(415);
        assertThat(exchange.body()).isEqualTo("{\"error\":\"unsupported_media_type\"}");
    }

    @Test
    @DisplayName("JSON with a charset parameter is accepted")
    void charsetParameter() {
        TestExchange exchange = service.send(TestExchange.withBody(HttpMethod.POST, LOGIN,
                "{\"email\":\"a@example.test\",\"password\":\"x\"}", "application/json; charset=utf-8"));

        assertThat(exchange.code()).isEqualTo(401);
    }

    @Test
    @DisplayName("a body above the limit is refused with 413 before it is read")
    void sizeLimit() {
        String padding = "x".repeat(JsonBodies.MAX_BYTES);
        TestExchange exchange = post("{\"email\":\"a@example.test\",\"password\":\"" + padding + "\"}");

        assertThat(exchange.code()).isEqualTo(413);
        assertThat(exchange.body()).isEqualTo("{\"error\":\"request_too_large\"}");
    }

    @Test
    @DisplayName("a missing body, malformed JSON, a non-object, trailing content and repeated fields are refused")
    void malformedBodies() {
        assertThat(service.send(TestExchange.of(HttpMethod.POST, LOGIN)).code()).isEqualTo(415);
        assertThat(post("").body()).isEqualTo(INVALID);
        for (String body : new String[] {
                "{", "[]", "\"text\"", "null", "42",
                "{\"email\":\"a@example.test\",\"password\":\"x\"} {}",
                "{\"email\":\"a@example.test\",\"email\":\"b@example.test\",\"password\":\"x\"}"}) {
            TestExchange exchange = post(body);

            assertThat(exchange.code()).as(body).isEqualTo(400);
            assertThat(exchange.body()).as(body).isEqualTo(INVALID);
        }
    }

    @Test
    @DisplayName("an unknown field, a missing field and a field of the wrong type are refused")
    void fieldChecks() {
        for (String body : new String[] {
                "{\"email\":\"a@example.test\",\"password\":\"x\",\"extra\":1}",
                "{\"email\":\"a@example.test\"}",
                "{\"email\":42,\"password\":\"x\"}",
                "{\"email\":\"a@example.test\",\"password\":[\"x\"]}",
                "{\"email\":\"a@example.test\",\"password\":null}",
                "{\"email\":\"  \",\"password\":\"x\"}"}) {
            TestExchange exchange = post(body);

            assertThat(exchange.code()).as(body).isEqualTo(400);
            assertThat(exchange.body()).as(body).isEqualTo(INVALID);
        }
    }

    @Test
    @DisplayName("a value a capability rejects is answered with the fixed code, never with the exception's text")
    void noExceptionTextIsEchoed() {
        TestExchange exchange = post("{\"email\":\"not-an-address\",\"password\":\"x\"}");

        assertThat(exchange.code()).isEqualTo(400);
        assertThat(exchange.body()).isEqualTo(INVALID);
    }

    @Test
    @DisplayName("every response forbids caching and sniffing")
    void responseHeaders() {
        TestExchange exchange = post("{\"email\":\"a@example.test\",\"password\":\"x\"}");

        assertThat(exchange.header("Cache-Control")).isEqualTo("no-store");
        assertThat(exchange.header("X-Content-Type-Options")).isEqualTo("nosniff");
        assertThat(exchange.header("Content-Type")).isEqualTo("application/json");
    }
}
