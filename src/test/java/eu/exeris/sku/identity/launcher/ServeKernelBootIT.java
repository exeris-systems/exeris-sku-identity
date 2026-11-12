package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.TestConfig;
import eu.exeris.sku.identity.support.process.FailingOnJoinPart;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The endings of serve that need a booted kernel, and so a developer licence: a clean stop, and a
 * service that fails after the kernel is up. Run with {@code -DexcludedGroups=kernel-boot} without one.
 */
@Tag("kernel-boot")
@DisplayName("serve with a booted kernel")
class ServeKernelBootIT {

    private static final String[] FAILURE_SIGNATURES = {
            "The kernel did not boot", "failed while starting", "failed after it began serving",
            "Stopping Identity failed", "Exception in thread \"main\""};

    /** 128 plus the signal number of SIGTERM, which is what a JVM stopped by it reports on Linux. */
    private static final int SIGTERM_STATUS = 143;

    private static String manifest;

    @BeforeAll
    static void requireLicence() {
        manifest = System.getenv(LaunchedProcess.DEVELOPER_LICENCE_VARIABLE);
        if (manifest == null || manifest.isBlank()) {
            throw new AssertionError(LaunchedProcess.DEVELOPER_LICENCE_VARIABLE + " is not set: a developer "
                    + "licence entitling exeris-sku-identity and its nine commercial capabilities is required "
                    + "to boot the kernel");
        }
    }

    private static Map<String, String> environment(PostgresSupport.Database database, int port,
                                                   String directory) {
        Map<String, String> env = LaunchedProcess.serviceEnvironment(database, port, TestConfig.env());
        env.put(LaunchedProcess.LICENCE_VARIABLE, manifest);
        env.put("EXERIS_ENVIRONMENT", "development");
        env.put("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY", directory);
        return env;
    }

    @Test
    @DisplayName("A termination signal stops a healthy service within a bound, closes the port and reports no failure")
    void stopOnRequest() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        int port = LaunchedProcess.freePort();
        Map<String, String> env = environment(database, port, InMemoryMembershipDirectory.class.getName());

        try (LaunchedProcess process = LaunchedProcess.start(env)) {
            ServeSupport.awaitHealthy(process, port);

            int status;
            try {
                status = process.terminate(60);
            } catch (AssertionError hung) {
                process.close();
                throw hung;
            }

            assertThat(process.isAlive()).isFalse();
            // A JVM ended by a termination signal reports 128 + 15 whatever main returned.
            assertThat(status).as(process.output()).isEqualTo(SIGTERM_STATUS);
            assertThat(process.output().split("Shutdown signal received", -1)).as("occurrences of the signal line")
                    .hasSize(2);
            assertThat(ServeSupport.accepts(port)).as("the port after the stop").isFalse();
            for (String signature : FAILURE_SIGNATURES) {
                assertThat(process.output()).doesNotContain(signature);
            }
        }
    }

    @Test
    @DisplayName("A part that fails after the kernel booted exits not completed, names only the class, never serves, and leaves the port free")
    void failureAfterTheKernelBooted() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        int port = LaunchedProcess.freePort();
        String marker = "marker-" + UUID.randomUUID();
        Map<String, String> failing = environment(database, port, FailingOnJoinPart.class.getName());
        failing.put(FailingOnJoinPart.MARKER_VARIABLE, marker);

        try (LaunchedProcess process = LaunchedProcess.start(failing)) {
            boolean answeredHealth = false;
            long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(90);
            while (process.isAlive() && System.nanoTime() < deadline) {
                answeredHealth |= ServeSupport.accepts(port) && healthAnswers(port);
                Thread.sleep(50);
            }
            int status = ServeSupport.awaitExitOrDestroy(process, 5);
            String output = process.output();

            assertThat(status).as(output).isEqualTo(IdentitySkuApplication.EXIT_NOT_COMPLETED);
            assertThat(output.lines().filter(line -> line.contains("failed while starting")))
                    .anySatisfy(line -> assertThat(line).contains("java.lang.IllegalStateException")
                            .containsPattern("SEVERE|ERROR"));
            assertThat(output).doesNotContain(marker).doesNotContain("host part failed")
                    .doesNotContain("Exception in thread \"main\"").doesNotContain("Kernel boot failed");
            assertThat(answeredHealth).as("/health answered while the service was failing").isFalse();
            assertThat(ServeSupport.accepts(port)).as("the port after the exit").isFalse();
        }

        // Everything the failed run held is released: a healthy service binds the same port at once.
        Map<String, String> healthy = environment(database, port, InMemoryMembershipDirectory.class.getName());
        try (LaunchedProcess second = LaunchedProcess.start(healthy)) {
            ServeSupport.awaitHealthy(second, port);
            assertThat(second.terminate(60)).isEqualTo(SIGTERM_STATUS);
        }
    }

    @Test
    @DisplayName("After a serve that had no licence, a serve with one binds the same port and the first left no listener")
    void portIsFreeAfterAKernelThatDidNotBoot() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        int port = LaunchedProcess.freePort();
        Map<String, String> unlicensed = environment(database, port, InMemoryMembershipDirectory.class.getName());
        unlicensed.remove(LaunchedProcess.LICENCE_VARIABLE);

        try (LaunchedProcess first = LaunchedProcess.start(unlicensed)) {
            assertThat(ServeSupport.awaitExitOrDestroy(first, 90)).as(first.output())
                    .isEqualTo(IdentitySkuApplication.EXIT_NOT_COMPLETED);
            assertThat(ServeSupport.accepts(port)).isFalse();
        }

        try (LaunchedProcess second = LaunchedProcess.start(
                environment(database, port, InMemoryMembershipDirectory.class.getName()))) {
            ServeSupport.awaitHealthy(second, port);
            assertThat(second.terminate(60)).isEqualTo(SIGTERM_STATUS);
        }
    }

    /** One probe on a connection of its own that is closed after the answer, so none is kept to be answered 503. */
    private static boolean healthAnswers(int port) {
        try {
            return ServeSupport.get(port, "/health") == 200;
        } catch (java.io.IOException | RuntimeException e) {
            return false;
        }
    }
}
