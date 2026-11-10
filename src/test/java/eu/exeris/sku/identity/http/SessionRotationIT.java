package eu.exeris.sku.identity.http;

import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.sku.identity.support.IdentityHarness;
import eu.exeris.sku.identity.support.IdentityHarness.Account;
import eu.exeris.sku.identity.support.TestExchange;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static eu.exeris.sku.identity.support.IdentityHarness.bearer;
import static eu.exeris.sku.identity.support.IdentityHarness.json;
import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Sessions and refresh tokens")
class SessionRotationIT {

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

    private static TestExchange refresh(String token) {
        return service.post(BASE + "/refresh", Map.of("refreshToken", token));
    }

    private static int sessionCount(String accessToken) {
        TestExchange list = service.send(HttpMethod.GET, BASE + "/sessions", bearer(accessToken));
        assertThat(list.code()).isEqualTo(200);
        return json(list).get("sessions").size();
    }

    @Test
    @DisplayName("a refresh token is exchanged for a successor and a new access token on the same session")
    void rotation() {
        JsonNode login = service.login(service.account());

        TestExchange rotated = refresh(login.get("refreshToken").stringValue());

        assertThat(rotated.code()).isEqualTo(200);
        JsonNode tokens = json(rotated);
        assertThat(tokens.get("refreshToken").stringValue()).isNotEqualTo(login.get("refreshToken").stringValue());
        assertThat(tokens.get("sessionId").stringValue()).isEqualTo(login.get("sessionId").stringValue());
        assertThat(service.send(HttpMethod.GET, BASE + "/sessions",
                bearer(tokens.get("accessToken").stringValue())).code()).isEqualTo(200);
    }

    @Test
    @DisplayName("the tenant of the token does not change at refresh")
    void tenantIsStable() {
        UUID tenant = UUID.randomUUID();
        JsonNode login = service.login(service.member(tenant, "admin"));

        JsonNode refreshed = json(refresh(login.get("refreshToken").stringValue()));

        for (JsonNode tokens : List.of(login, refreshed)) {
            String payload = tokens.get("accessToken").stringValue().split("\\.")[1];
            assertThat(new String(Base64.getUrlDecoder().decode(payload))).contains(tenant.toString());
        }
    }

    @Test
    @DisplayName("using a refresh token a second time revokes the session and every token of it")
    void reuseRevokesTheSession() {
        Account account = service.account();
        JsonNode first = service.login(account);
        String sessionBefore = first.get("sessionId").stringValue();
        String other = service.accessToken(account);
        JsonNode second = json(refresh(first.get("refreshToken").stringValue()));

        TestExchange replay = refresh(first.get("refreshToken").stringValue());
        TestExchange successor = refresh(second.get("refreshToken").stringValue());

        assertThat(replay.code()).isEqualTo(401);
        assertThat(replay.body()).isEqualTo("{\"error\":\"invalid_refresh_token\"}");
        assertThat(successor.code()).as("the successor was issued for the revoked session").isEqualTo(401);
        TestExchange list = service.send(HttpMethod.GET, BASE + "/sessions", bearer(other));
        assertThat(list.body()).doesNotContain(sessionBefore);
        assertThat(sessionCount(other)).isEqualTo(1);
    }

    @Test
    @DisplayName("of many concurrent presentations of one refresh token exactly one succeeds")
    void concurrentRotation() throws Exception {
        JsonNode login = service.login(service.account());
        String token = login.get("refreshToken").stringValue();
        int threads = 8;
        CountDownLatch go = new CountDownLatch(1);
        List<Future<Integer>> results = new ArrayList<>();
        try (ExecutorService pool = Executors.newFixedThreadPool(threads)) {
            for (int i = 0; i < threads; i++) {
                results.add(pool.submit(() -> {
                    go.await();
                    return refresh(token).code();
                }));
            }
            go.countDown();
            List<Integer> codes = new ArrayList<>();
            for (Future<Integer> result : results) {
                codes.add(result.get());
            }
            assertThat(codes.stream().filter(c -> c == 200).count()).isEqualTo(1);
            assertThat(codes.stream().filter(c -> c == 401).count()).isEqualTo(threads - 1);
        }
    }

    @Test
    @DisplayName("a session records the peer address and the user agent of the sign-in")
    void sessionRecordsTheClient() {
        Account account = service.account();
        TestExchange login = service.send(TestExchange.json(HttpMethod.POST, BASE + "/login",
                IdentityHarness.write(IdentityHarness.credentials(account)),
                new HttpHeader("User-Agent", "test-client/1.0")).from("203.0.113.30"));
        assertThat(login.code()).isEqualTo(200);

        TestExchange list = service.send(HttpMethod.GET, BASE + "/sessions",
                bearer(json(login).get("accessToken").stringValue()));

        JsonNode session = json(list).get("sessions").get(0);
        assertThat(session.get("ipAddress").stringValue()).isEqualTo("203.0.113.30");
        assertThat(session.get("userAgent").stringValue()).isEqualTo("test-client/1.0");
        assertThat(session.get("current").booleanValue()).isTrue();
    }

    @Test
    @DisplayName("an unknown refresh token is refused")
    void unknownToken() {
        TestExchange exchange = refresh("unknown-" + UUID.randomUUID());

        assertThat(exchange.code()).isEqualTo(401);
        assertThat(exchange.body()).isEqualTo("{\"error\":\"invalid_refresh_token\"}");
    }

    @Test
    @DisplayName("a session can be listed, revoked, and then no longer refreshes")
    void revokeOwnSession() {
        Account account = service.account();
        JsonNode keep = service.login(account);
        JsonNode drop = service.login(account);
        String access = keep.get("accessToken").stringValue();
        assertThat(sessionCount(access)).isEqualTo(2);

        TestExchange revoked = service.post(BASE + "/sessions/revoke",
                Map.of("sessionId", drop.get("sessionId").stringValue()), bearer(access));

        assertThat(revoked.code()).isEqualTo(200);
        assertThat(sessionCount(access)).isEqualTo(1);
        assertThat(refresh(drop.get("refreshToken").stringValue()).code()).isEqualTo(401);
        assertThat(refresh(keep.get("refreshToken").stringValue()).code()).isEqualTo(200);
    }

    @Test
    @DisplayName("revoking every session ends the caller's refresh tokens")
    void revokeAll() {
        Account account = service.account();
        JsonNode one = service.login(account);
        JsonNode two = service.login(account);

        TestExchange exchange = service.send(HttpMethod.POST, BASE + "/sessions/revoke-all",
                bearer(one.get("accessToken").stringValue()));

        assertThat(exchange.code()).isEqualTo(200);
        assertThat(json(exchange).get("revoked").intValue()).isEqualTo(2);
        assertThat(refresh(one.get("refreshToken").stringValue()).code()).isEqualTo(401);
        assertThat(refresh(two.get("refreshToken").stringValue()).code()).isEqualTo(401);
    }
}
