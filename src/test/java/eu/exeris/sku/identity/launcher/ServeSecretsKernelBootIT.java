package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.launcher.BootstrapOwnerSupport.Run;
import eu.exeris.sku.identity.support.IdentityHarness;
import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.TestConfig;
import eu.exeris.sku.identity.support.process.MarkerFailingMembershipDirectory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.sql.Connection;
import java.sql.Statement;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * No secret reaches the output of {@code serve} once the kernel is asked to boot, and none reaches a client
 * or the log when a request fails. These tests boot a real kernel and need the developer licence.
 */
@Tag("kernel-boot")
@DisplayName("serve with a kernel: no secret reaches the output")
class ServeSecretsKernelBootIT {

    private static Run serve(Map<String, String> env) throws Exception {
        try (LaunchedProcess process = LaunchedProcess.start(env)) {
            int status = ServeSupport.awaitExitOrDestroy(process, 120);
            return new Run(status, process.output());
        }
    }

    @Test
    @DisplayName("(c) A kernel that cannot open its pool fails with its message, which may quote the URL: the service password is withheld")
    void kernelBootFailureQuotingTheUrl() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        String role = "limited_" + SecretForms.lowerCaseMarker();
        String password = SecretForms.marker();
        try (Connection owner = database.owner(); Statement statement = owner.createStatement()) {
            statement.execute("CREATE ROLE " + role + " LOGIN PASSWORD '" + password
                    + "' NOSUPERUSER NOBYPASSRLS CONNECTION LIMIT 1");
        }
        Map<String, String> env = ServeSupport.licensedEnvironment(database, LaunchedProcess.freePort(),
                InMemoryMembershipDirectory.class.getName());
        env.put("EXERIS_DATABASE_USER", role);
        env.put("EXERIS_DATABASE_PASSWORD", password);
        env.put("EXERIS_DATABASE_URL", database.serviceUrl() + "?ssl=false");
        env.put("EXERIS_DATABASE_MAX_POOL_SIZE", "10");

        Run run = serve(env);

        assertThat(run.status()).as(run.output()).isEqualTo(IdentitySkuApplication.EXIT_NOT_COMPLETED);
        assertThat(run.output()).contains("The kernel did not boot");
        SecretForms.assertNoLeaks(run.output(), "kernel boot failure", Map.of("PASSWORD", password));
    }

    @Test
    @DisplayName("(d) A request that fails with an exception whose messages hold a marker: the log holds two class names, no marker and no stack frame, and the response holds no marker")
    void failedRequest() throws Exception {
        String marker = SecretForms.marker();
        Map<String, String> identity = new HashMap<>(TestConfig.env());
        IdentityHarness.Account account;
        PostgresSupport.Database database;
        try (IdentityHarness seed = IdentityHarness.start(identity)) {
            account = seed.account();
            database = seed.database;
        }
        int port = LaunchedProcess.freePort();
        Map<String, String> env = ServeSupport.licensedEnvironment(database, port,
                MarkerFailingMembershipDirectory.class.getName());
        env.putAll(identity);
        env.put(MarkerFailingMembershipDirectory.MARKER_VARIABLE, marker);

        try (LaunchedProcess process = LaunchedProcess.start(env)) {
            ServeSupport.awaitHealthy(process, port);
            HttpClient client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
            HttpResponse<String> response = client.send(HttpRequest.newBuilder(
                            URI.create("http://127.0.0.1:" + port + "/api/v1/auth/login"))
                    .timeout(Duration.ofSeconds(10)).header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(IdentityHarness.write(IdentityHarness.credentials(account))))
                    .build(), HttpResponse.BodyHandlers.ofString());
            process.terminate(60);
            String output = process.output();

            assertThat(response.statusCode()).as(response.body()).isEqualTo(500);
            SecretForms.assertNoLeaks(response.body() + response.headers(), "the response", Map.of("MARKER", marker));
            SecretForms.assertNoLeaks(output, "the log", Map.of("MARKER", marker));
            assertThat(output.lines().filter(line -> line.contains("request failed")).toList())
                    .as("the failure is logged once, as two class names")
                    .singleElement().asString().contains("request failed (java.lang.IllegalStateException, "
                            + "root cause java.sql.SQLException)");
            assertThat(output).doesNotContainPattern("(?m)^\\s+at [a-z]").doesNotContain("Caused by");
        }
    }
}
