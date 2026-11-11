package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * How long a healthy {@code serve} takes to stop after SIGTERM, measured from the signal to the death of the
 * process. The kernel holds its own stop for the HTTP idle timeout while a connection that was answered 503
 * during the start is kept open, so each test says which connections the service has seen.
 */
@Tag("kernel-boot")
@DisplayName("Stopping serve with SIGTERM")
class ServeStopIT {

    private static final int SIGTERM_STATUS = 143;
    private static final Duration PROMPT = Duration.ofSeconds(5);
    /** Above the kernel's idle timeout of 30 s, below a hang. */
    private static final Duration KERNEL_IDLE_TIMEOUT_BOUND = Duration.ofSeconds(45);
    private static final Duration IDLE_BEFORE_SIGNAL = Duration.ofSeconds(1);
    /** How often a health probe asks. The kernel's delay shows at a probe's cadence, not when the connection is polled in a tight loop. */
    private static final Duration PROBE_INTERVAL = Duration.ofMillis(250);

    private static LaunchedProcess startHealthy(int port) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        Map<String, String> env = ServeSupport.licensedEnvironment(database, port,
                InMemoryMembershipDirectory.class.getName());
        return LaunchedProcess.start(env);
    }

    private static void assertCleanStop(LaunchedProcess.Stopped stopped, LaunchedProcess process, int port,
                                        Duration bound) {
        String output = process.output();
        System.out.println("[stop-time] " + stopped.took().toMillis() + " ms");
        assertThat(stopped.status()).as(output).isEqualTo(SIGTERM_STATUS);
        assertThat(stopped.took()).as("from SIGTERM to the death of the process" + System.lineSeparator() + output)
                .isLessThan(bound);
        assertThat(output.split("Shutdown signal received", -1)).as("occurrences of the signal line").hasSize(2);
        assertThat(output).doesNotContain("Stopping Identity failed").doesNotContain("Exception in thread")
                .doesNotContain("failed after it began serving");
        assertThat(ServeSupport.accepts(port)).as("the port after the stop").isFalse();
    }

    @Test
    @DisplayName("A healthy service that no client ever connected to stops within five seconds")
    void stopsPromptlyWhenNobodyConnected() throws Exception {
        int port = LaunchedProcess.freePort();
        try (LaunchedProcess process = startHealthy(port)) {
            // Waiting for the log line connects to nothing, so no client has seen the starting phase.
            ServeSupport.awaitRunning(process);

            LaunchedProcess.Stopped stopped = process.terminateTimed(60);

            assertCleanStop(stopped, process, port, PROMPT);
        }
    }

    @Test
    @DisplayName("A service that answered several 200s on one kept-alive connection opened after it was running stops within five seconds")
    void stopsPromptlyAfterKeptAliveRequestsThatWereAllAnswered() throws Exception {
        int port = LaunchedProcess.freePort();
        try (LaunchedProcess process = startHealthy(port)) {
            // The connection is opened after the "running on" line, so it never sees a 503.
            ServeSupport.awaitRunning(process);
            try (ServeSupport.KeptAlive connection = new ServeSupport.KeptAlive(port)) {
                for (int i = 0; i < 5; i++) {
                    assertThat(connection.get("/health")).isEqualTo(200);
                }

                // A client holds its connection while it is idle; the stop must not depend on a request in flight.
                Thread.sleep(IDLE_BEFORE_SIGNAL.toMillis());
                LaunchedProcess.Stopped stopped = process.terminateTimed(60);

                assertCleanStop(stopped, process, port, PROMPT);
            }
        }
    }

    @Test
    @DisplayName("A termination signal while a host part is still joining the transactions, before the composition starts, ends the process at once with the signal's status and no failure")
    void stopsWhileTheStartIsInProgress() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        int port = LaunchedProcess.freePort();
        Map<String, String> env = ServeSupport.licensedEnvironment(database, port,
                eu.exeris.sku.identity.support.process.ThrowingOnJoinPart.class.getName());
        env.put(eu.exeris.sku.identity.support.process.ThrowingOnJoinPart.KIND_VARIABLE,
                eu.exeris.sku.identity.support.process.ThrowingOnJoinPart.PARK);
        try (LaunchedProcess process = LaunchedProcess.start(env)) {
            long deadline = System.nanoTime() + Duration.ofSeconds(90).toNanos();
            while (!process.output().contains(
                    eu.exeris.sku.identity.support.process.ThrowingOnJoinPart.PARKED_LINE)) {
                if (!process.isAlive() || System.nanoTime() > deadline) {
                    throw new AssertionError("the part never parked" + System.lineSeparator() + process.output());
                }
                Thread.sleep(10);
            }

            LaunchedProcess.Stopped stopped = process.terminateTimed(60);

            assertCleanStop(stopped, process, port, PROMPT);
            assertThat(process.output()).doesNotContain(ServeSupport.RUNNING_LINE);
        }
    }

    /**
     * Pins a known behaviour of the kernel, not a property of this service: a kept-alive connection that was
     * answered 503 while the service was starting keeps the kernel's stop waiting for its HTTP idle timeout
     * (about 30 s). The assertion is an upper bound only, so the test goes on passing, and shows a shorter
     * time in its output, when the kernel stops waiting for such a connection; it fails only on a hang.
     */
    @Test
    @DisplayName("Characterisation of a kernel behaviour: a kept-alive connection answered 503 while starting delays the stop, but not past 45 seconds")
    void keptAliveConnectionAnswered503WhileStartingDelaysTheStopWithinTheIdleTimeout() throws Exception {
        for (int attempt = 1; attempt <= 3; attempt++) {
            int port = LaunchedProcess.freePort();
            try (LaunchedProcess process = startHealthy(port)) {
                if (!openedDuringStartAnd503ThenAnd200(process, port)) {
                    continue;
                }
                LaunchedProcess.Stopped stopped = process.terminateTimed(120);

                System.out.println("[stop-time-after-503] " + stopped.took().toMillis() + " ms");
                assertThat(stopped.status()).as(process.output()).isEqualTo(SIGTERM_STATUS);
                assertThat(stopped.took()).as("a stop must not hang" + System.lineSeparator() + process.output())
                        .isLessThan(KERNEL_IDLE_TIMEOUT_BOUND);
                assertThat(ServeSupport.accepts(port)).as("the port after the stop").isFalse();
                return;
            }
        }
        throw new AssertionError("no attempt saw a 503 and then a 200 on one connection; the start was never slow "
                + "enough to answer 503 on a connection kept from before it");
    }

    /**
     * Pins a second known behaviour of the kernel, beyond the one above: a kept-alive connection that carried
     * a POST answered 401 also holds the stop until its idle timeout, while a kept-alive connection that
     * carried a GET answered 401 or 404 does not. Upper bound only, for the same reason.
     */
    @Test
    @DisplayName("Characterisation of a kernel behaviour: a kept-alive connection that carried a POST answered 401 delays the stop, but not past 45 seconds")
    void keptAliveConnectionThatCarriedARefusedPostDelaysTheStopWithinTheIdleTimeout() throws Exception {
        int port = LaunchedProcess.freePort();
        try (LaunchedProcess process = startHealthy(port)) {
            ServeSupport.awaitRunning(process);
            try (ServeSupport.KeptAlive connection = new ServeSupport.KeptAlive(port)) {
                assertThat(connection.post("/api/v1/auth/login",
                        "{\"email\":\"nobody@example.test\",\"password\":\"not-a-password\"}")).isEqualTo(401);
                Thread.sleep(IDLE_BEFORE_SIGNAL.toMillis());

                LaunchedProcess.Stopped stopped = process.terminateTimed(120);

                System.out.println("[stop-time-after-refused-post] " + stopped.took().toMillis() + " ms");
                assertThat(stopped.status()).as(process.output()).isEqualTo(SIGTERM_STATUS);
                assertThat(stopped.took()).as("a stop must not hang" + System.lineSeparator() + process.output())
                        .isLessThan(KERNEL_IDLE_TIMEOUT_BOUND);
            }
        }
    }

    /**
     * Keeps one connection from the first moment the port accepts until /health answers 200 on it, and says
     * whether that connection was answered 503 on the way. The connection is left open.
     */
    private static boolean openedDuringStartAnd503ThenAnd200(LaunchedProcess process, int port) throws Exception {
        long deadline = System.nanoTime() + Duration.ofSeconds(90).toNanos();
        ServeSupport.KeptAlive connection = null;
        int unavailable = 0;
        while (System.nanoTime() < deadline) {
            if (!process.isAlive()) {
                throw new AssertionError("the service exited before it was healthy" + System.lineSeparator()
                        + process.output());
            }
            try {
                if (connection == null) {
                    connection = new ServeSupport.KeptAlive(port);
                    unavailable = 0;
                }
                int status = connection.get("/health");
                if (status == 503) {
                    unavailable++;
                } else if (status == 200) {
                    keep(connection);
                    return unavailable > 0;
                }
            } catch (IOException notYet) {
                closeQuietly(connection);
                connection = null;
            }
            Thread.sleep(PROBE_INTERVAL.toMillis());
        }
        throw new AssertionError("the service did not become healthy" + System.lineSeparator() + process.output());
    }

    private static final java.util.List<ServeSupport.KeptAlive> KEPT = new java.util.concurrent.CopyOnWriteArrayList<>();

    private static void keep(ServeSupport.KeptAlive connection) {
        KEPT.add(connection);
    }

    private static void closeQuietly(ServeSupport.KeptAlive connection) {
        if (connection != null) {
            try {
                connection.close();
            } catch (IOException ignored) {
                // nothing is left to release
            }
        }
    }

    @org.junit.jupiter.api.AfterAll
    static void releaseKeptConnections() {
        KEPT.forEach(ServeStopIT::closeQuietly);
        KEPT.clear();
    }
}
