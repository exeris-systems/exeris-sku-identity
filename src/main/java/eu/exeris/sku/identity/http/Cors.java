package eu.exeris.sku.identity.http;

import eu.exeris.caps.corspolicy.api.CorsDecision;
import eu.exeris.caps.corspolicy.api.CorsPolicies;
import eu.exeris.caps.corspolicy.api.CorsPolicy;
import eu.exeris.caps.corspolicy.api.CorsRequest;
import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpResponse;
import eu.exeris.kernel.spi.http.HttpStatus;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Cross-origin access for browser clients, decided by the CORS policy capability over the configured origins.
 *
 * <p>With no origin configured nothing is allowed and no CORS header is ever written. Credentials are never
 * allowed: tokens travel in the {@code Authorization} header, not in cookies.
 */
final class Cors {

    private static final List<String> METHODS = List.of("GET", "POST", "OPTIONS");
    private static final List<String> HEADERS = List.of("Authorization", "Content-Type");

    private final CorsPolicy policy;

    private Cors(CorsPolicy policy) {
        this.policy = policy;
    }

    /** CORS over the origins; disabled when there are none. */
    static Cors of(List<String> origins) {
        if (origins.isEmpty()) {
            return new Cors(null);
        }
        return new Cors(CorsPolicies.builder()
                .allowOrigins(origins)
                .methods(METHODS)
                .headers(HEADERS)
                .maxAge(Duration.ofMinutes(10))
                .allowCredentials(false)
                .build());
    }

    boolean enabled() {
        return policy != null;
    }

    /** The CORS headers for an actual request, empty when the origin is absent or not allowed. */
    List<HttpHeader> responseHeaders(HttpExchange exchange) {
        if (policy == null) {
            return List.of();
        }
        Optional<String> origin = exchange.request().firstHeader("Origin");
        if (origin.isEmpty() || origin.get().isBlank()) {
            return List.of();
        }
        CorsDecision decision = policy.evaluate(
                CorsRequest.simple(origin.get().trim(), exchange.request().method().name()));
        return decision.allowed() ? toHeaders(decision.headers()) : List.of();
    }

    /** Answers a preflight request: 204 with the policy's headers when allowed, 403 otherwise. */
    void preflight(HttpExchange exchange) {
        Optional<String> origin = exchange.request().firstHeader("Origin");
        Optional<String> method = exchange.request().firstHeader("Access-Control-Request-Method");
        if (policy == null || origin.isEmpty() || method.isEmpty()) {
            exchange.respond(HttpStatus.FORBIDDEN);
            return;
        }
        List<String> requested = exchange.request().firstHeader("Access-Control-Request-Headers")
                .map(value -> Arrays.stream(value.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList())
                .orElse(List.of());
        CorsDecision decision = policy.evaluate(
                CorsRequest.preflight(origin.get().trim(), method.get().trim(), requested));
        if (!decision.allowed()) {
            exchange.respond(HttpStatus.FORBIDDEN);
            return;
        }
        List<HttpHeader> headers = new ArrayList<>(toHeaders(decision.headers()));
        headers.add(new HttpHeader("Content-Length", "0"));
        exchange.respond(HttpResponse.noBody(HttpStatus.NO_CONTENT, exchange.request().version(), headers));
    }

    private static List<HttpHeader> toHeaders(Map<String, String> headers) {
        List<HttpHeader> result = new ArrayList<>(headers.size());
        headers.forEach((name, value) -> result.add(new HttpHeader(name, value)));
        return result;
    }
}
