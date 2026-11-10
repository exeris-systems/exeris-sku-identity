package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.IdentityHarness;
import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.TestConfig;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The whole service in a JVM of its own: the kernel boots, the executor and scheduler come from it, and
 * requests arrive over a socket. Booting the kernel needs a licence manifest, so the class carries the
 * {@code kernel-boot} tag; a developer without one runs {@code mvn verify -DexcludedGroups=kernel-boot}.
 */
@Tag("kernel-boot")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@DisplayName("IdentitySkuApplication in a process")
class IdentityProcessIT {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final HttpClient CLIENT = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(2)).build();

    private static LaunchedProcess process;
    private static int port;
    private static IdentityHarness.Account account;

    @BeforeAll
    static void startService() throws Exception {
        String manifest = System.getenv(LaunchedProcess.LICENCE_VARIABLE);
        if (manifest == null || manifest.isBlank()) {
            throw new AssertionError(LaunchedProcess.LICENCE_VARIABLE + " is not set: a developer licence "
                    + "entitling exeris-sku-identity and its nine commercial capabilities is required to boot "
                    + "the kernel");
        }
        Map<String, String> identity = TestConfig.env();
        PostgresSupport.Database database;
        // The account exists before the service starts, created by the same key material it will run with.
        try (IdentityHarness seed = IdentityHarness.start(identity)) {
            account = seed.account();
            database = seed.database;
        }
        identity.put("EXERIS_TOKEN_ISSUER_MANUAL_ROTATION", "false");

        port = LaunchedProcess.freePort();
        Map<String, String> env = LaunchedProcess.serviceEnvironment(database, port, identity);
        env.put(LaunchedProcess.LICENCE_VARIABLE, manifest);
        process = LaunchedProcess.start(env);
        awaitHealthy();
    }

    @AfterAll
    static void stopService() {
        if (process != null) {
            process.close();
        }
    }

    private static HttpResponse<String> send(HttpRequest.Builder request) throws Exception {
        return CLIENT.send(request.timeout(Duration.ofSeconds(10)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpRequest.Builder to(String path) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path));
    }

    private static void awaitHealthy() throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(90);
        while (System.nanoTime() < deadline) {
            if (!process.isAlive()) {
                throw new AssertionError("the service exited before it was healthy" + System.lineSeparator()
                        + process.output());
            }
            try {
                if (send(to("/health").GET()).statusCode() == 200) {
                    return;
                }
            } catch (Exception notUpYet) {
                // keep waiting
            }
            Thread.sleep(250);
        }
        throw new AssertionError("the service did not become healthy" + System.lineSeparator() + process.output());
    }

    private static HttpResponse<String> login() throws Exception {
        String body = IdentityHarness.write(IdentityHarness.credentials(account));
        return send(to("/api/v1/auth/login").header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)));
    }

    @Test
    @Order(1)
    @DisplayName("/health answers 200 and the kernel marks the response as a development licence")
    void health() throws Exception {
        HttpResponse<String> response = send(to("/health").GET());

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("Exeris-License")).hasValue("development");
    }

    @Test
    @Order(2)
    @DisplayName("A login through the kernel's transactional executor returns a token the service itself accepts")
    void endToEndLogin() throws Exception {
        HttpResponse<String> response = login();
        assertThat(response.statusCode()).as(response.body() + System.lineSeparator() + process.output())
                .isEqualTo(200);
        JsonNode body = JSON.readTree(response.body());
        String token = body.get("accessToken").stringValue();
        assertThat(token).isNotBlank();

        HttpResponse<String> sessions = send(to("/api/v1/auth/sessions").header("Authorization", "Bearer " + token)
                .GET());
        assertThat(sessions.statusCode()).as(sessions.body() + System.lineSeparator() + process.output())
                .isEqualTo(200);
        assertThat(send(to("/api/v1/auth/sessions").GET()).statusCode()).isEqualTo(401);
    }

    @Test
    @Order(3)
    @DisplayName("The key set is public and holds the signing key the scheduler-run issuer created")
    void jwksIsPublic() throws Exception {
        HttpResponse<String> response = send(to("/.well-known/jwks.json").GET());

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(JSON.readTree(response.body()).get("keys")).isNotEmpty();
    }

    @Test
    @Order(4)
    @DisplayName("A wrong password is refused by the same process")
    void wrongPassword() throws Exception {
        String body = IdentityHarness.write(Map.of("email", account.email(), "password", "not-" + account.password()));
        HttpResponse<String> response = send(to("/api/v1/auth/login").header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)));

        assertThat(response.statusCode()).isEqualTo(401);
    }

    @Test
    @Order(99)
    @DisplayName("A termination signal ends the process and the listener stops accepting connections")
    void terminationEndsTheProcess() throws Exception {
        process.terminate(60);

        assertThat(process.isAlive()).isFalse();
        assertThatThrownBy(() -> send(to("/health").GET())).isInstanceOf(java.io.IOException.class);
    }
}
