package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The notice the shutdown hook writes goes to the standard error, once per stop, in every run: a loss would
 * show in a repeated stop.
 */
@Tag("kernel-boot")
@DisplayName("The shutdown notice")
class ServeShutdownNoticeIT {

    private static final String NOTICE = "Shutdown signal received, draining";
    private static final int RUNS = 36;
    private static final int PARALLEL = 4;

    private static String stopOnce() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        int port = LaunchedProcess.freePort();
        Map<String, String> env = ServeSupport.licensedEnvironment(database, port, InMemoryMembershipDirectory.class.getName());
        try (LaunchedProcess process = LaunchedProcess.start(env)) {
            ServeSupport.awaitRunning(process);
            LaunchedProcess.Stopped stopped = process.terminateTimed(60);
            String output = process.output();
            assertThat(stopped.status()).as(output).isEqualTo(143);
            return output;
        }
    }

    @Test
    @DisplayName("After a signal exactly one notice is written, as a bare line on the standard error, in each of 36 runs")
    void exactlyOneNoticeInEveryRun() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(PARALLEL);
        try {
            List<Future<String>> runs = new ArrayList<>();
            for (int i = 0; i < RUNS; i++) {
                runs.add(pool.submit(ServeShutdownNoticeIT::stopOnce));
            }
            int index = 0;
            for (Future<String> run : runs) {
                String output = run.get(10, TimeUnit.MINUTES);
                long notices = output.lines().filter(line -> line.contains(NOTICE)).count();
                assertThat(notices).as("run %d" + System.lineSeparator() + "%s", index, output).isEqualTo(1);
                assertThat(output.lines()).as("run %d: the notice is not a log record", index).contains(NOTICE);
                index++;
            }
        } finally {
            pool.shutdownNow();
        }
    }
}
