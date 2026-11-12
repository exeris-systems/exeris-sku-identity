package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.process.ThrowingOnJoinPart;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The endings of {@code serve} that an {@link Error} raised after the kernel booted produces. A thrown
 * instance stands for the real thing; nothing is exhausted.
 */
@Tag("kernel-boot")
@DisplayName("serve ends on an Error")
class ServeErrorEndingsIT {

    private static final int SIGTERM_STATUS = 143;
    private static final Duration HALT_BOUND = Duration.ofSeconds(10);

    private static Map<String, String> throwing(PostgresSupport.Database database, int port, String kind,
                                                String marker) {
        Map<String, String> env = ServeSupport.licensedEnvironment(database, port,
                ThrowingOnJoinPart.class.getName());
        env.put(ThrowingOnJoinPart.KIND_VARIABLE, kind);
        env.put(ThrowingOnJoinPart.MARKER_VARIABLE, marker);
        return env;
    }

    @Test
    @DisplayName("A class that cannot be loaded exits not completed with one error line naming the class and no message, trace or uncaught exception; the port is free for the next serve")
    void errorThatIsNotFatal() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        int port = LaunchedProcess.freePort();
        String marker = "marker-" + UUID.randomUUID();

        try (LaunchedProcess process = LaunchedProcess.start(
                throwing(database, port, ThrowingOnJoinPart.NO_CLASS_DEF, marker))) {
            int status = ServeSupport.awaitExitOrDestroy(process, 90);
            String output = process.output();

            assertThat(status).as(output).isEqualTo(IdentitySkuApplication.EXIT_NOT_COMPLETED);
            List<String> naming = output.lines().filter(line -> line.contains("java.lang.NoClassDefFoundError"))
                    .toList();
            assertThat(naming).as("lines naming the error" + System.lineSeparator() + output).hasSize(1);
            assertThat(naming.getFirst()).containsPattern("SEVERE|ERROR");
            assertThat(output).doesNotContain(marker).doesNotContain("host part error")
                    .doesNotContain("Exception in thread").doesNotContain("Caused by")
                    .doesNotContainPattern("(?m)^\\s+at [a-z]");
            assertThat(ServeSupport.accepts(port)).as("the port after the exit").isFalse();
        }

        try (LaunchedProcess second = LaunchedProcess.start(ServeSupport.licensedEnvironment(database, port,
                InMemoryMembershipDirectory.class.getName()))) {
            ServeSupport.awaitHealthy(second, port);
            assertThat(second.terminate(60)).isEqualTo(SIGTERM_STATUS);
        }
    }

    @Test
    @DisplayName("A fatal VM error that reaches main exits not completed within ten seconds, never 1 and never a hang")
    void fatalVirtualMachineError() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        int port = LaunchedProcess.freePort();
        String marker = "marker-" + UUID.randomUUID();

        try (LaunchedProcess process = LaunchedProcess.start(
                throwing(database, port, ThrowingOnJoinPart.OUT_OF_MEMORY, marker))) {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(90);
            while (!process.output().contains(ThrowingOnJoinPart.THROWING_LINE) && process.isAlive()
                    && System.nanoTime() < deadline) {
                Thread.sleep(10);
            }
            long thrown = System.nanoTime();
            while (process.isAlive() && System.nanoTime() - thrown < HALT_BOUND.toNanos()) {
                Thread.sleep(10);
            }
            String output = process.output();
            if (process.isAlive()) {
                process.close();
                throw new AssertionError("serve was still alive " + HALT_BOUND.toSeconds()
                        + " s after the error was thrown, destroyed" + System.lineSeparator() + output);
            }
            int status = process.awaitExit(5);
            System.out.println("[halt-time] " + Duration.ofNanos(System.nanoTime() - thrown).toMillis() + " ms");

            assertThat(status).as(output).isEqualTo(IdentitySkuApplication.EXIT_NOT_COMPLETED);
            assertThat(output).contains("java.lang.OutOfMemoryError").doesNotContain(marker)
                    .doesNotContain("Exception in thread").doesNotContain("Shutdown signal received");
            assertThat(ServeSupport.accepts(port)).as("the port after the exit").isFalse();
        }
    }
}
