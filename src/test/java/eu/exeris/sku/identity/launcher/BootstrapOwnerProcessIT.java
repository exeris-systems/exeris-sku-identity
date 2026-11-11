package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.IdentityHarness;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.TestConfig;
import eu.exeris.sku.identity.support.process.FailingMembershipDirectory;
import eu.exeris.sku.identity.support.process.FileMembershipDirectory;
import eu.exeris.sku.identity.support.process.ParkingMembershipDirectory;
import eu.exeris.sku.identity.support.process.OutboxInvitationDelivery;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static eu.exeris.sku.identity.launcher.BootstrapOwnerSupport.*;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The command end to end, with a real kernel, one test for each way it ends once the kernel has booted: it
 * needs a licence manifest, so the class carries the {@code kernel-boot} tag. A developer without a licence runs {@code mvn verify -DexcludedGroups=kernel-boot}.
 */
@Tag("kernel-boot")
@DisplayName("bootstrap-owner with a booted kernel")
class BootstrapOwnerProcessIT {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final HttpClient CLIENT = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(2)).build();

    private static String manifest() {
        String manifest = System.getenv(LaunchedProcess.DEVELOPER_LICENCE_VARIABLE);
        if (manifest == null || manifest.isBlank()) {
            throw new AssertionError(LaunchedProcess.DEVELOPER_LICENCE_VARIABLE + " is not set: a developer licence "
                    + "entitling exeris-sku-identity and its nine commercial capabilities is required to boot "
                    + "the kernel");
        }
        return manifest;
    }

    private static Map<String, String> licensed(PostgresSupport.Database database, Path passwordFile)
            throws Exception {
        Map<String, String> env = environment(database, passwordFile);
        env.put("EXERIS_TOKEN_ISSUER_MANUAL_ROTATION", "false");
        env.put(LaunchedProcess.LICENCE_VARIABLE, manifest());
        return env;
    }

    private static Map<String, String> hosted(Map<String, String> env, Path hostDirectory, UUID tenant) {
        withDirectory(env, hostDirectory, tenant);
        env.put("EXERIS_IDENTITY_INVITATION_DELIVERY", OutboxInvitationDelivery.class.getName());
        env.put("IDENTITY_TEST_PROBE_TENANT_A", UUID.randomUUID().toString());
        env.put("IDENTITY_TEST_PROBE_TENANT_B", UUID.randomUUID().toString());
        return env;
    }

    /** The command's result, and whether anything ever accepted a connection on the service port meanwhile. */
    private record Watched(Run run, boolean portWasBound) {
    }

    private static Watched runWatchingThePort(Map<String, String> env) throws Exception {
        int port = Integer.parseInt(env.get("EXERIS_HTTP_PORT"));
        AtomicBoolean bound = new AtomicBoolean();
        try (LaunchedProcess process = LaunchedProcess.start(env, "bootstrap-owner")) {
            Thread watcher = Thread.ofPlatform().daemon().start(() -> {
                while (process.isAlive()) {
                    try (Socket socket = new Socket()) {
                        socket.connect(new InetSocketAddress("127.0.0.1", port), 100);
                        bound.set(true);
                        return;
                    } catch (java.io.IOException refused) {
                        // expected: nothing listens
                    }
                    try {
                        Thread.sleep(10);
                    } catch (InterruptedException e) {
                        return;
                    }
                }
            });
            int status = process.awaitExit(180);
            watcher.join(5_000);
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", port), 200);
                bound.set(true);
            } catch (java.io.IOException refused) {
                // expected
            }
            return new Watched(new Run(status, process.output()), bound.get());
        }
    }

    private static HttpResponse<String> send(HttpRequest.Builder request) throws Exception {
        return CLIENT.send(request.timeout(Duration.ofSeconds(10)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpRequest.Builder to(int port, String path) {
        return HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path));
    }

    private static void awaitHealthy(LaunchedProcess process, int port) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(120);
        while (System.nanoTime() < deadline) {
            if (!process.isAlive()) {
                throw new AssertionError("the service exited before it was healthy" + System.lineSeparator()
                        + process.output());
            }
            try {
                if (send(to(port, "/health").GET()).statusCode() == 200) {
                    return;
                }
            } catch (Exception notUpYet) {
                // keep waiting
            }
            Thread.sleep(250);
        }
        throw new AssertionError("the service did not become healthy" + System.lineSeparator() + process.output());
    }

    private static HttpResponse<String> postJson(int port, String path, Object body, String bearer) throws Exception {
        HttpRequest.Builder request = to(port, path).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body)));
        if (bearer != null) {
            request.header("Authorization", "Bearer " + bearer);
        }
        return send(request);
    }

    private static String accessToken(LaunchedProcess process, int port, String email, String password)
            throws Exception {
        HttpResponse<String> response = postJson(port, "/api/v1/auth/login",
                Map.of("email", email, "password", password), null);
        assertThat(response.statusCode()).as(response.body() + System.lineSeparator() + process.output())
                .isEqualTo(200);
        return JSON.readTree(response.body()).get("accessToken").stringValue();
    }

    private static JsonNode claims(String accessToken) {
        return JSON.readTree(new String(Base64.getUrlDecoder().decode(accessToken.split("\\.")[1]),
                StandardCharsets.UTF_8));
    }

    @Test
    @DisplayName("It creates the owner, grants owner in the tenant, refuses a second run, binds no port, and serve then signs the owner in")
    void firstAccountEndToEnd(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        Path hostDirectory = Files.createDirectory(dir.resolve("host"));
        UUID tenant = UUID.randomUUID();
        String password = new String(TestConfig.randomPassword());
        Path file = passwordFile(dir, password + "\r\n");
        Map<String, String> env = hosted(licensed(database, file), hostDirectory, tenant);
        String email = env.get(EMAIL);

        Watched first = runWatchingThePort(env);

        assertThat(first.run().status()).as(first.run().output()).isEqualTo(OK);
        assertThat(first.portWasBound()).as("the HTTP port was bound").isFalse();
        assertThat(accounts(database)).isEqualTo(1);
        Credential row = onlyCredential(database);
        assertThat(row.loginIdentifier()).isEqualTo(email.toLowerCase());
        assertThat(row.verified()).isTrue();
        assertThat(row.verifiedAtSet()).isTrue();
        assertThat(grants(hostDirectory)).containsExactly(row.subject() + "|" + tenant + "|owner");
        assertThat(first.run().output()).contains(row.subject().toString());
        assertNoSecrets(first.run().output(), password, password + "\r\n", database.servicePassword(), email,
                email.toLowerCase());

        Run second = run(env);

        assertThat(second.status()).as(second.output()).isEqualTo(ACCOUNTS_EXIST);
        assertThat(accounts(database)).isEqualTo(1);
        assertThat(grants(hostDirectory)).hasSize(1);
        assertNoSecrets(second.output(), password, database.servicePassword(), email, email.toLowerCase());

        int port = Integer.parseInt(env.get("EXERIS_HTTP_PORT"));
        try (LaunchedProcess service = LaunchedProcess.start(env)) {
            awaitHealthy(service, port);
            String token = accessToken(service, port, email, password);
            JsonNode claims = claims(token);
            assertThat(claims.get("tid").stringValue()).isEqualTo(tenant.toString());
            assertThat(claims.get("roles").get(0).stringValue()).isEqualTo("owner");
            assertThat(claims.get("scope").stringValue()).contains("invitations:write");

            HttpResponse<String> issued = postJson(port, "/api/v1/auth/invitations",
                    Map.of("email", "invitee-" + UUID.randomUUID().toString().substring(0, 8) + "@example.test",
                            "role", "member"), token);
            assertThat(issued.statusCode()).as(issued.body() + System.lineSeparator() + service.output())
                    .isEqualTo(201);
        }
    }

    private static void assertNoSecrets(String output, String... secrets) {
        assertThat(output).doesNotContain("eyJ");
        for (String secret : secrets) {
            assertThat(output).doesNotContain(secret);
        }
    }

    @Test
    @DisplayName("Without a directory it creates the account with a warning, and its token names no tenant, role or scope")
    void noDirectory(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        String password = new String(TestConfig.randomPassword());
        Map<String, String> env = licensed(database, passwordFile(dir, password));
        String email = env.get(EMAIL);

        Watched result = runWatchingThePort(env);

        assertThat(result.run().status()).as(result.run().output()).isEqualTo(OK);
        assertThat(result.portWasBound()).isFalse();
        assertThat(accounts(database)).isEqualTo(1);
        assertThat(result.run().output()).contains("belongs to no tenant", "no role or scope", "cannot issue invitations");
        assertNoSecrets(result.run().output(), password, database.servicePassword(), email, email.toLowerCase());

        int port = Integer.parseInt(env.get("EXERIS_HTTP_PORT"));
        try (LaunchedProcess service = LaunchedProcess.start(env)) {
            awaitHealthy(service, port);
            JsonNode claims = claims(accessToken(service, port, email, password));
            assertThat(claims.has("tid")).isFalse();
            assertThat(claims.has("roles")).isFalse();
            assertThat(claims.has("scope")).isFalse();
        }
    }

    @Test
    @DisplayName("An address the credential store rejects exits 78, names the key, and creates nothing")
    void invalidAddress(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        Path hostDirectory = Files.createDirectory(dir.resolve("host"));
        Map<String, String> env = hosted(licensed(database,
                passwordFile(dir, new String(TestConfig.randomPassword()))), hostDirectory, UUID.randomUUID());
        String bad = "not-an-address-" + UUID.randomUUID();
        env.put(EMAIL, bad);

        Run run = run(env);

        assertThat(run.status()).as(run.output()).isEqualTo(CONFIG);
        assertThat(run.output()).contains(EMAIL).doesNotContain(bad);
        assertThat(accounts(database)).isZero();
        assertThat(grants(hostDirectory)).isEmpty();
    }

    @Test
    @DisplayName("A directory whose grant throws exits 70 with no account and without printing its message; a later run succeeds")
    void failingDirectory(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        Path hostDirectory = Files.createDirectory(dir.resolve("host"));
        UUID tenant = UUID.randomUUID();
        String password = new String(TestConfig.randomPassword());
        Map<String, String> env = hosted(licensed(database, passwordFile(dir, password)), hostDirectory, tenant);
        env.put("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY", FailingMembershipDirectory.class.getName());

        Run failed = run(env);

        assertThat(failed.status()).as(failed.output()).isEqualTo(NOT_COMPLETED);
        assertThat(failed.output()).doesNotContain(FailingMembershipDirectory.MESSAGE);
        assertThat(accounts(database)).isZero();
        assertNoSecrets(failed.output(), password, database.servicePassword(), env.get(EMAIL));

        env.put("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY", FileMembershipDirectory.class.getName());
        Run again = run(env);

        assertThat(again.status()).as(again.output()).isEqualTo(OK);
        assertThat(accounts(database)).isEqualTo(1);
        assertThat(grants(hostDirectory)).hasSize(1);
    }

    @Test
    @DisplayName("A database where migrate has not run exits 65 after the boot, creates no table and no grant")
    void notMigrated(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.emptyDatabase();
        Path hostDirectory = Files.createDirectory(dir.resolve("host"));
        String password = new String(TestConfig.randomPassword());
        Map<String, String> env = hosted(licensed(database, passwordFile(dir, password)), hostDirectory,
                UUID.randomUUID());

        Run run = run(env);

        assertThat(run.status()).as(run.output()).isEqualTo(NOT_MIGRATED);
        assertThat(tables(database)).isEmpty();
        assertThat(grants(hostDirectory)).isEmpty();
        assertNoSecrets(run.output(), password, database.servicePassword(), env.get(EMAIL));
    }

    @Test
    @DisplayName("A service role that may not read, or may not insert into, the credential table exits 65 and writes nothing")
    void missingPrivilege(@TempDir Path dir) throws Exception {
        for (String privilege : new String[] {"SELECT", "INSERT"}) {
            PostgresSupport.Database database = PostgresSupport.newDatabase();
            revoke(database, privilege);
            Path hostDirectory = Files.createDirectory(dir.resolve("host-" + privilege));
            String password = new String(TestConfig.randomPassword());
            Map<String, String> env = hosted(licensed(database, passwordFile(dir, password)), hostDirectory,
                    UUID.randomUUID());

            Run run = run(env);

            assertThat(run.status()).as(privilege + System.lineSeparator() + run.output()).isEqualTo(NOT_MIGRATED);
            assertThat(accounts(database)).as(privilege).isZero();
            assertThat(grants(hostDirectory)).as(privilege).isEmpty();
            assertNoSecrets(run.output(), password, database.servicePassword(), env.get(EMAIL));
        }
    }

    @Test
    @DisplayName("A database that already holds an account exits 73 and adds no account and no grant")
    void accountsExist(@TempDir Path dir) throws Exception {
        try (IdentityHarness service = IdentityHarness.start()) {
            service.account();
            Path hostDirectory = Files.createDirectory(dir.resolve("host"));
            String password = new String(TestConfig.randomPassword());
            Map<String, String> env = hosted(licensed(service.database, passwordFile(dir, password)), hostDirectory,
                    UUID.randomUUID());

            Run run = run(env);

            assertThat(run.status()).as(run.output()).isEqualTo(ACCOUNTS_EXIST);
            assertThat(accounts(service.database)).isEqualTo(1);
            assertThat(grants(hostDirectory)).isEmpty();
            assertNoSecrets(run.output(), password, service.database.servicePassword(), env.get(EMAIL));
        }
    }

    @Test
    @DisplayName("A credential table under row-level security exits 78 with a message that says so, and writes nothing")
    void rowLevelSecurity(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        enableRowLevelSecurity(database);
        Path hostDirectory = Files.createDirectory(dir.resolve("host"));
        String password = new String(TestConfig.randomPassword());
        Map<String, String> env = hosted(licensed(database, passwordFile(dir, password)), hostDirectory,
                UUID.randomUUID());

        Run run = run(env);

        assertThat(run.status()).as(run.output()).isEqualTo(CONFIG);
        assertThat(run.output()).contains("credential table must not be under row-level security");
        assertThat(accounts(database)).isZero();
        assertThat(grants(hostDirectory)).isEmpty();
        assertNoSecrets(run.output(), password, database.servicePassword(), env.get(EMAIL));
    }

    @Test
    @DisplayName("A run that holds the first account uncommitted makes a second run wait on the table, then find it: exits 0 and 73, one account, one grant")
    void overlappingRuns(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        Path hostDirectory = Files.createDirectory(dir.resolve("host"));
        UUID tenant = UUID.randomUUID();
        String password = new String(TestConfig.randomPassword());
        Map<String, String> first = hosted(licensed(database, passwordFile(dir, password)), hostDirectory, tenant);
        first.put("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY", ParkingMembershipDirectory.class.getName());
        Map<String, String> second = copy(first);
        second.put(EMAIL, email());
        second.put("EXERIS_HTTP_PORT", String.valueOf(LaunchedProcess.freePort()));

        try (LaunchedProcess a = LaunchedProcess.start(first, "bootstrap-owner")) {
            awaitParked(a, hostDirectory);
            try (LaunchedProcess b = LaunchedProcess.start(second, "bootstrap-owner")) {
                String waiting = awaitWaiter(database, b);

                assertThat(waiting).containsIgnoringCase("credential_records");
                assertThat(a.isAlive()).as("the first run holds its transaction open").isTrue();
                assertThat(b.isAlive()).as("the second run waits for the first").isTrue();
                assertThat(accounts(database)).as("nothing is committed yet").isZero();

                Files.createFile(hostDirectory.resolve(ParkingMembershipDirectory.RELEASE));

                assertThat(a.awaitExit(180)).as(a.output()).isEqualTo(OK);
                assertThat(b.awaitExit(180)).as(b.output()).isEqualTo(ACCOUNTS_EXIST);
                assertNoSecrets(a.output() + b.output(), password, database.servicePassword(), first.get(EMAIL),
                        second.get(EMAIL));
            }
        }

        assertThat(accounts(database)).isEqualTo(1);
        Credential row = onlyCredential(database);
        assertThat(grants(hostDirectory)).containsExactly(row.subject() + "|" + tenant + "|owner");
    }

    /**
     * Two runs started together on fresh databases. The overlap is left to chance, so this is statistical; the
     * test above forces it.
     */
    @Test
    @DisplayName("Ten pairs of runs started together each exit 0 and 73 and leave one account and one grant")
    void pairsStartedTogether(@TempDir Path dir) throws Exception {
        for (int round = 0; round < 10; round++) {
            PostgresSupport.Database database = PostgresSupport.newDatabase();
            Path hostDirectory = Files.createDirectory(dir.resolve("host-" + round));
            UUID tenant = UUID.randomUUID();
            Path file = passwordFile(dir, new String(TestConfig.randomPassword()));
            Map<String, String> first = hosted(licensed(database, file), hostDirectory, tenant);
            Map<String, String> second = copy(first);
            second.put(EMAIL, email());
            second.put("EXERIS_HTTP_PORT", String.valueOf(LaunchedProcess.freePort()));

            try (LaunchedProcess a = LaunchedProcess.start(first, "bootstrap-owner");
                 LaunchedProcess b = LaunchedProcess.start(second, "bootstrap-owner")) {
                List<Integer> statuses = new ArrayList<>(List.of(a.awaitExit(180), b.awaitExit(180)));
                statuses.sort(Integer::compare);

                assertThat(statuses).as("round " + round + System.lineSeparator() + a.output()
                        + System.lineSeparator() + b.output()).containsExactly(OK, ACCOUNTS_EXIST);
            }

            assertThat(accounts(database)).as("round " + round).isEqualTo(1);
            assertThat(grants(hostDirectory)).as("round " + round).hasSize(1)
                    .containsExactly(onlyCredential(database).subject() + "|" + tenant + "|owner");
        }
    }

    private static void awaitParked(LaunchedProcess process, Path hostDirectory) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(180);
        while (!Files.exists(hostDirectory.resolve(ParkingMembershipDirectory.PARKED))) {
            if (!process.isAlive() || System.nanoTime() > deadline) {
                throw new AssertionError("the first run never reached its grant" + System.lineSeparator()
                        + process.output());
            }
            Thread.sleep(20);
        }
    }

    private static String awaitWaiter(PostgresSupport.Database database, LaunchedProcess second) throws Exception {
        try {
            return awaitCredentialTableWaiter(database);
        } catch (AssertionError never) {
            throw new AssertionError(never.getMessage() + System.lineSeparator() + second.output(), never);
        }
    }
}
