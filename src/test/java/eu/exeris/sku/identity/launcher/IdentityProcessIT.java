package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.IdentityHarness;
import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.TestConfig;
import eu.exeris.sku.identity.support.process.FileMembershipDirectory;
import eu.exeris.sku.identity.support.process.HostFiles;
import eu.exeris.sku.identity.support.process.OutboxInvitationDelivery;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

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

    private static PostgresSupport.Database serviceDatabase;
    private static LaunchedProcess process;
    private static int port;
    private static IdentityHarness.Account account;
    private static IdentityHarness.Account adminA;
    private static IdentityHarness.Account adminB;
    private static final UUID TENANT_A = UUID.randomUUID();
    private static final UUID TENANT_B = UUID.randomUUID();
    private static Path hostDirectory;
    private static String tokenOfB;
    private static String addressOfB;

    @BeforeAll
    static void startService() throws Exception {
        String manifest = System.getenv(LaunchedProcess.DEVELOPER_LICENCE_VARIABLE);
        if (manifest == null || manifest.isBlank()) {
            throw new AssertionError(LaunchedProcess.DEVELOPER_LICENCE_VARIABLE + " is not set: a developer licence "
                    + "entitling exeris-sku-identity and its nine commercial capabilities is required to boot "
                    + "the kernel");
        }
        Map<String, String> identity = TestConfig.env();
        PostgresSupport.Database database;
        hostDirectory = Files.createTempDirectory("identity-host-");
        // The accounts exist before the service starts, created by the same key material it will run with.
        try (IdentityHarness seed = IdentityHarness.start(identity)) {
            account = seed.account();
            adminA = seed.account();
            adminB = seed.account();
            database = seed.database;
        }
        Files.writeString(hostDirectory.resolve("memberships"),
                adminA.subject() + "|" + TENANT_A + "|admin" + System.lineSeparator()
                        + adminB.subject() + "|" + TENANT_B + "|admin" + System.lineSeparator());
        identity.put("EXERIS_TOKEN_ISSUER_MANUAL_ROTATION", "false");
        // Every sign-in of the class comes from one address; the login group's limit is not what it tests.
        identity.put("EXERIS_RATELIMIT_LOGIN_CAPACITY", "50");

        port = LaunchedProcess.freePort();
        Map<String, String> env = LaunchedProcess.serviceEnvironment(database, port, identity);
        env.put(LaunchedProcess.LICENCE_VARIABLE, manifest);
        env.put("EXERIS_ENVIRONMENT", "development");
        env.put("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY", FileMembershipDirectory.class.getName());
        env.put("EXERIS_IDENTITY_INVITATION_DELIVERY", OutboxInvitationDelivery.class.getName());
        env.put(HostFiles.DIRECTORY_VARIABLE, hostDirectory.toString());
        env.put("IDENTITY_TEST_PROBE_TENANT_A", TENANT_A.toString());
        env.put("IDENTITY_TEST_PROBE_TENANT_B", TENANT_B.toString());
        serviceDatabase = database;
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

    /** Waits for the "running on" line and probes once on a closed connection; see {@link ServeSupport}. */
    private static void awaitHealthy() throws Exception {
        ServeSupport.awaitHealthy(process, port);
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

    private static HttpResponse<String> postJson(String path, Object body, String bearerToken) throws Exception {
        HttpRequest.Builder request = to(path).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(IdentityHarness.write(body)));
        if (bearerToken != null) {
            request.header("Authorization", "Bearer " + bearerToken);
        }
        return send(request);
    }

    private static String signIn(IdentityHarness.Account who) throws Exception {
        HttpResponse<String> response = postJson("/api/v1/auth/login", IdentityHarness.credentials(who), null);
        assertThat(response.statusCode()).as(response.body() + System.lineSeparator() + process.output())
                .isEqualTo(200);
        return JSON.readTree(response.body()).get("accessToken").stringValue();
    }

    private static String claims(String accessToken) {
        return new String(Base64.getUrlDecoder().decode(accessToken.split("\\.")[1]), StandardCharsets.UTF_8);
    }

    private static String delivered(String email) {
        return HostFiles.lines(hostDirectory, "outbox").stream().filter(line -> line.startsWith(email + "|"))
                .map(line -> line.substring(email.length() + 1)).findFirst().orElseThrow();
    }

    private static String address() {
        return "invitee-" + UUID.randomUUID().toString().substring(0, 10) + "@example.test";
    }

    private static long invitationsOf(UUID tenant) throws Exception {
        try (Connection owner = serviceDatabase.owner();
             PreparedStatement count = owner.prepareStatement("SELECT count(*) FROM invitations WHERE tenant_id = ?::uuid")) {
            count.setString(1, tenant.toString());
            try (ResultSet rows = count.executeQuery()) {
                rows.next();
                return rows.getLong(1);
            }
        }
    }

    /** The probe lines of a label, split as {@code label, bound tenant, visible of A, visible of B}. */
    private static List<String[]> probes(String label) {
        return HostFiles.lines(hostDirectory, "probe").stream().map(line -> line.split("\\|"))
                .filter(parts -> parts[0].equals(label)).toList();
    }

    @Test
    @Order(5)
    @DisplayName("Tenant B's admin invites into B on the kernel's executor, and the row is committed")
    void invitationIntoTenantB() throws Exception {
        addressOfB = address();
        String token = signIn(adminB);
        assertThat(claims(token)).contains(TENANT_B.toString());

        HttpResponse<String> issued = postJson("/api/v1/auth/invitations",
                Map.of("email", addressOfB, "role", "member"), token);

        assertThat(issued.statusCode()).as(issued.body() + System.lineSeparator() + process.output())
                .isEqualTo(201);
        tokenOfB = delivered(addressOfB);
        assertThat(invitationsOf(TENANT_B)).as("committed, seen as the owner role").isEqualTo(1);
    }

    @Test
    @Order(6)
    @DisplayName("Tenant A's admin invites into A: the token goes to the outbox and not to the response, and B's row stays hidden")
    void invitationIntoTenantA() throws Exception {
        String token = signIn(adminA);
        assertThat(claims(token)).contains(TENANT_A.toString());
        String email = address();

        HttpResponse<String> issued = postJson("/api/v1/auth/invitations",
                Map.of("email", email, "role", "member"), token);

        assertThat(issued.statusCode()).as(issued.body() + System.lineSeparator() + process.output())
                .isEqualTo(201);
        assertThat(JSON.readTree(issued.body()).has("token")).isFalse();
        assertThat(delivered(email)).isNotBlank().isNotEqualTo(tokenOfB);
        assertThat(invitationsOf(TENANT_A)).isEqualTo(1);
        String[] probe = probes("issue").getLast();
        assertThat(probe[1]).as("the kernel executor is bound to the caller's tenant").isEqualTo(TENANT_A.toString());
        assertThat(probe[2]).as("A's request reads its own tenant's rows").matches("[1-9][0-9]*");
        assertThat(probe[3]).as("tenant B's committed row is invisible to A's request").isEqualTo("0");
    }

    @Test
    @Order(7)
    @DisplayName("Accepting binds the invitation's tenant: the invitee signs in to it, and B's invitation is not visible")
    void acceptanceInTenantA() throws Exception {
        String email = address();
        postJson("/api/v1/auth/invitations", Map.of("email", email, "role", "member"), signIn(adminA));
        String token = delivered(email);
        String password = new String(TestConfig.randomPassword());

        HttpResponse<String> accepted = postJson("/api/v1/auth/invitations/accept",
                Map.of("tenantId", TENANT_A.toString(), "token", token, "email", email, "password", password), null);

        assertThat(accepted.statusCode()).as(accepted.body() + System.lineSeparator() + process.output())
                .isEqualTo(201);
        String[] probe = probes("accept").getLast();
        assertThat(probe[1]).as("the kernel executor is bound to the invitation's tenant")
                .isEqualTo(TENANT_A.toString());
        assertThat(probe[2]).as("the acceptance reads its own tenant's rows").matches("[1-9][0-9]*");
        assertThat(probe[3]).as("tenant B's row is invisible while accepting into A").isEqualTo("0");
        String invitee = claims(signIn(new IdentityHarness.Account(UUID.randomUUID(), email, password)));
        assertThat(invitee).contains(TENANT_A.toString()).contains("\"member\"");
    }

    @Test
    @Order(8)
    @DisplayName("B's token opens nothing in tenant A, and still opens B afterwards")
    void foreignTokenIsRefused() throws Exception {
        String password = new String(TestConfig.randomPassword());

        HttpResponse<String> inA = postJson("/api/v1/auth/invitations/accept",
                Map.of("tenantId", TENANT_A.toString(), "token", tokenOfB, "email", addressOfB,
                        "password", password), null);
        HttpResponse<String> inB = postJson("/api/v1/auth/invitations/accept",
                Map.of("tenantId", TENANT_B.toString(), "token", tokenOfB, "email", addressOfB,
                        "password", password), null);

        assertThat(inA.statusCode()).isEqualTo(400);
        assertThat(inA.body()).isEqualTo("{\"error\":\"invalid_invitation\"}");
        assertThat(inB.statusCode()).as(inB.body() + System.lineSeparator() + process.output()).isEqualTo(201);
    }

    @Test
    @Order(9)
    @DisplayName("No token, and no hash of one, appears in the process output")
    void outputCarriesNoToken() {
        String output = process.output();

        for (String line : HostFiles.lines(hostDirectory, "outbox")) {
            String token = line.substring(line.indexOf('|') + 1);
            assertThat(output).doesNotContain(token).doesNotContain(token.replaceFirst("^inv_", ""));
        }
    }

    @Test
    @Order(10)
    @DisplayName("A kernel-encoded body arrives with one Content-Length that counts its bytes and one JSON Content-Type")
    void kernelEncodedBody() throws Exception {
        HttpResponse<byte[]> health = CLIENT.send(to("/health").GET().timeout(Duration.ofSeconds(10)).build(),
                HttpResponse.BodyHandlers.ofByteArray());
        HttpResponse<byte[]> refused = CLIENT.send(to("/api/v1/auth/login").header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"email\":\"zażółć@example.test\",\"password\":\"x\"}"))
                .timeout(Duration.ofSeconds(10)).build(), HttpResponse.BodyHandlers.ofByteArray());

        for (HttpResponse<byte[]> response : List.of(health, refused)) {
            assertThat(response.body()).isNotEmpty();
            assertThat(response.headers().allValues("Content-Length"))
                    .containsExactly(String.valueOf(response.body().length));
            assertThat(response.headers().allValues("Content-Type")).hasSize(1);
            assertThat(response.headers().firstValue("Content-Type").orElseThrow()).startsWith("application/json");
            assertThat(response.headers().allValues("Cache-Control")).containsExactly("no-store");
            JSON.readTree(new String(response.body(), StandardCharsets.UTF_8));
        }
        assertThat(new String(health.body(), StandardCharsets.UTF_8)).isEqualTo("{\"status\":\"UP\"}");
    }

    @Test
    @Order(99)
    @DisplayName("A termination signal ends the process and the listener stops accepting connections")
    void terminationEndsTheProcess() throws Exception {
        // The client's connections are released first, as a proxy drains its own before the service is stopped:
        // the kernel holds its stop for a kept-alive connection (see ServeStopIT for what that costs).
        CLIENT.close();

        process.terminate(60);

        assertThat(process.isAlive()).isFalse();
        assertThat(ServeSupport.accepts(port)).as("the port after the stop").isFalse();
    }
}
