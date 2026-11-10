package eu.exeris.sku.identity.http;

import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRoute;
import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.RouteRequirement;
import eu.exeris.sku.identity.support.IdentityHarness;
import eu.exeris.sku.identity.support.TestExchange;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("The route table")
class RouteTableTest {

    private static final String JWKS = "GET /.well-known/jwks.json";

    private static final Set<String> EXPECTED = Set.of(
            "GET /health",
            JWKS,
            "POST /api/v1/auth/login",
            "POST /api/v1/auth/mfa/verify",
            "POST /api/v1/auth/refresh",
            "POST /api/v1/auth/password/reset-request",
            "POST /api/v1/auth/password/reset",
            "POST /api/v1/auth/verification/send",
            "POST /api/v1/auth/verification/verify",
            "POST /api/v1/auth/invitations/accept",
            "POST /api/v1/auth/password/change",
            "POST /api/v1/auth/mfa/totp/enrollment",
            "POST /api/v1/auth/mfa/totp/enrollment/confirm",
            "POST /api/v1/auth/mfa/recovery-codes",
            "GET /api/v1/auth/sessions",
            "POST /api/v1/auth/sessions/revoke",
            "POST /api/v1/auth/sessions/revoke-all",
            "POST /api/v1/auth/invitations");

    private static IdentityHarness service;
    private static IdentityHarness otherService;

    @BeforeAll
    static void start() throws Exception {
        service = IdentityHarness.start();
        otherService = IdentityHarness.start();
    }

    @AfterAll
    static void stop() {
        service.close();
        otherService.close();
    }

    private static String key(ApiSurfaceRoute route) {
        return route.method().name() + " " + route.pathPattern();
    }

    private static Map<String, RouteRequirement.Kind> kinds() {
        return service.registry().routes().stream().collect(Collectors.toMap(
                RouteTableTest::key, route -> route.requirements().get(0).kind()));
    }

    @Test
    @DisplayName("is exactly the documented set of routes")
    void documentedRoutes() {
        assertThat(kinds().keySet()).containsExactlyInAnyOrderElementsOf(EXPECTED);
        assertThat(IdentityRoutes.tableKeys()).hasSize(EXPECTED.size() - 1)
                .doesNotContain(JWKS);
    }

    @Test
    @DisplayName("declares one non-abstaining requirement on every route")
    void everyRouteDeclaresARequirement() {
        for (ApiSurfaceRoute route : service.registry().routes()) {
            assertThat(route.requirements()).as(key(route)).hasSize(1);
            assertThat(route.requirements().get(0).isAbstention()).as(key(route)).isFalse();
        }
    }

    @Test
    @DisplayName("names as anonymous exactly the routes that are permitAll")
    void anonymousSetIsThePermitAllSet() {
        Set<String> permitAll = kinds().entrySet().stream()
                .filter(e -> e.getValue() == RouteRequirement.Kind.PERMIT_ALL)
                .map(Map.Entry::getKey).collect(Collectors.toCollection(TreeSet::new));
        Set<String> anonymous = new TreeSet<>(new IdentityRoutes(service.config).anonymousRoutes());
        anonymous.add(JWKS);

        assertThat(anonymous).isEqualTo(permitAll);
    }

    @Test
    @DisplayName("puts the invitation route behind a scope and the other private routes behind a token")
    void privateRoutes() {
        Map<String, RouteRequirement.Kind> kinds = kinds();

        assertThat(kinds.get("POST /api/v1/auth/invitations")).isEqualTo(RouteRequirement.Kind.ANY_SCOPE);
        assertThat(kinds.entrySet().stream().filter(e -> e.getValue() == RouteRequirement.Kind.AUTHENTICATED)
                .map(Map.Entry::getKey)).containsExactlyInAnyOrder(
                "POST /api/v1/auth/password/change",
                "POST /api/v1/auth/mfa/totp/enrollment",
                "POST /api/v1/auth/mfa/totp/enrollment/confirm",
                "POST /api/v1/auth/mfa/recovery-codes",
                "GET /api/v1/auth/sessions",
                "POST /api/v1/auth/sessions/revoke",
                "POST /api/v1/auth/sessions/revoke-all");
    }

    @Test
    @DisplayName("registers every route the rate limit is configured for")
    void rateLimitedRoutesExist() {
        Set<String> limited = service.config.rateLimit().groups().stream()
                .flatMap(group -> group.routes().stream()).collect(Collectors.toSet());

        assertThat(limited).isNotEmpty();
        assertThat(kinds().keySet()).containsAll(limited);
        assertThat(limited).allSatisfy(route ->
                assertThat(kinds().get(route)).as(route).isEqualTo(RouteRequirement.Kind.PERMIT_ALL));
    }

    @Test
    @DisplayName("is frozen once the service has started")
    void registryIsFrozen() {
        ApiSurfaceRoute late = ApiSurfaceRoute.builder()
                .method(HttpMethod.GET).pathPattern("/late").actionName("late")
                .requirements(List.of(RouteRequirement.permitAll()))
                .handler(exchange -> { })
                .build();

        assertThatThrownBy(() -> service.registry().registerRoute(late)).isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("refuses a request without a token on every private route")
    void privateRoutesRefuseAnonymousCallers() {
        for (String route : protectedRoutes()) {
            TestExchange exchange = request(route);

            service.send(exchange);

            assertThat(exchange.code()).as(route).isEqualTo(401);
        }
    }

    @Test
    @DisplayName("refuses a token that is garbage, or signed by another service, on every private route")
    void privateRoutesRefuseForeignTokens() throws Exception {
        String foreign = otherService.accessToken(otherService.account());

        for (String route : protectedRoutes()) {
            for (String token : List.of("not-a-token", foreign)) {
                TestExchange exchange = request(route, IdentityHarness.bearer(token));

                service.send(exchange);

                assertThat(exchange.code()).as(route).isEqualTo(401);
            }
        }
    }

    @Test
    @DisplayName("lets an anonymous caller reach every public route, and answers a malformed body with 400")
    void publicRoutesAreReachable() {
        for (String route : kinds().entrySet().stream()
                .filter(e -> e.getValue() == RouteRequirement.Kind.PERMIT_ALL)
                .map(Map.Entry::getKey).sorted().toList()) {
            if (route.equals(JWKS) || route.equals("GET /health")) {
                TestExchange exchange = request(route);
                service.send(exchange);
                assertThat(exchange.code()).as(route).isEqualTo(200);
            } else {
                TestExchange exchange = TestExchange.json(HttpMethod.POST, route.substring(5), "{}");
                service.send(exchange);
                assertThat(exchange.code()).as(route).isEqualTo(400);
                assertThat(exchange.body()).isEqualTo("{\"error\":\"invalid_request\"}");
            }
        }
    }

    @Test
    @DisplayName("answers a method the path does not take with 405")
    void wrongMethod() {
        assertThat(service.send(HttpMethod.GET, "/api/v1/auth/login").code()).isEqualTo(405);
        assertThat(service.send(HttpMethod.DELETE, "/api/v1/auth/sessions").code()).isEqualTo(405);
    }

    @Test
    @DisplayName("serves the key set and health without a token")
    void keySetAndHealth() {
        assertThat(service.send(HttpMethod.GET, "/.well-known/jwks.json").body()).contains("\"keys\"");
        assertThat(service.send(HttpMethod.GET, "/health").body()).isEqualTo("{\"status\":\"UP\"}");
    }

    @Test
    @DisplayName("refuses a query string on a route that takes none")
    void queryStringsAreRefused() {
        String token = service.accessToken(service.account());

        TestExchange exchange = service.send(HttpMethod.GET,
                "/api/v1/auth/sessions?subjectId=" + UUID.randomUUID(), IdentityHarness.bearer(token));

        assertThat(exchange.code()).isIn(400, 404);
    }

    private static List<String> protectedRoutes() {
        return kinds().entrySet().stream()
                .filter(e -> e.getValue() != RouteRequirement.Kind.PERMIT_ALL)
                .map(Map.Entry::getKey).sorted().toList();
    }

    private static TestExchange request(String route, HttpHeader... headers) {
        HttpMethod method = HttpMethod.valueOf(route.substring(0, route.indexOf(' ')));
        String path = route.substring(route.indexOf(' ') + 1);
        return method == HttpMethod.GET
                ? TestExchange.of(method, path, headers)
                : TestExchange.json(method, path, "{}", headers);
    }
}
