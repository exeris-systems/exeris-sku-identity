package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.process.FailingStopPart;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A stop that fails, in a launched service. The failure is put in place from inside the process once it
 * serves, see {@link FailingStopPart}; the process is then stopped by SIGTERM, which the shutdown hook
 * answers, or by an interrupt of the serving thread, which that thread answers. The failure of the stop is
 * reported once, by whichever thread performed the stop, as a constant and a class name.
 *
 * <p>An uneventful stop is covered by {@code ServeStopIT} (no failure line, one signal line, status 143)
 * and {@code ServeShutdownNoticeIT} (exactly one notice in each of many stops).
 */
@Tag("kernel-boot")
@DisplayName("A stop that fails")
class ServeStopFailureIT {

    private static final String NOTICE = "Shutdown signal received, draining";
    private static final String FAILED = "Stopping Identity failed (";
    private static final int SIGTERM_STATUS = 143;
    private static final Duration PROMPT = Duration.ofSeconds(30);

    private record Run(int status, Duration took, String output, String marker) {
        List<String> lines() {
            return output.lines().toList();
        }

        List<String> failureLines() {
            return lines().stream().filter(line -> line.contains(FAILED)).toList();
        }
    }

    private static Map<String, String> environment(String fails, String marker, boolean removeHandlers,
                                                   boolean interruptServer) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        Map<String, String> env = ServeSupport.licensedEnvironment(database, LaunchedProcess.freePort(),
                FailingStopPart.class.getName());
        env.put(FailingStopPart.FAIL_VARIABLE, fails);
        env.put(FailingStopPart.MARKER_VARIABLE, marker);
        env.put(FailingStopPart.REMOVE_HANDLERS_VARIABLE, String.valueOf(removeHandlers));
        env.put(FailingStopPart.INTERRUPT_VARIABLE, String.valueOf(interruptServer));
        return env;
    }

    private static void awaitArranged(LaunchedProcess process) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(30).toNanos();
        while (!process.output().contains(FailingStopPart.ARRANGED_LINE)) {
            if (process.output().contains(FailingStopPart.FAILED_LINE) || !process.isAlive()
                    || System.nanoTime() > deadline) {
                throw new AssertionError("the failures were not arranged" + System.lineSeparator() + process.output());
            }
            Thread.sleep(10);
        }
    }

    private static final List<String> OPENED = List.of("--add-opens=java.base/java.lang=ALL-UNNAMED");

    /** Starts the service, arranges the failures, and stops it with SIGTERM. */
    private static Run signalled(String fails, boolean removeHandlers) throws Exception {
        String marker = "marker-" + UUID.randomUUID();
        try (LaunchedProcess process = LaunchedProcess.start(environment(fails, marker, removeHandlers, false),
                OPENED)) {
            ServeSupport.awaitRunning(process);
            awaitArranged(process);
            LaunchedProcess.Stopped stopped = process.terminateTimed(60);
            return new Run(stopped.status(), stopped.took(), process.output(), marker);
        }
    }

    private static void assertReportedOnce(Run run, Class<?> failure) {
        String output = run.output();
        assertThat(run.status()).as(output).isEqualTo(SIGTERM_STATUS);
        assertThat(run.took()).as("from SIGTERM to the death of the process" + System.lineSeparator() + output)
                .isLessThan(PROMPT);
        assertThat(run.failureLines()).as("the failure lines" + System.lineSeparator() + output)
                .containsExactly(FAILED + failure.getName() + ")");
        assertThat(run.lines().indexOf(NOTICE)).as("the notice is a line of its own" + System.lineSeparator() + output)
                .isNotNegative()
                .isLessThan(run.lines().indexOf(FAILED + failure.getName() + ")"));
        assertThat(output.split(NOTICE, -1)).as("occurrences of the notice").hasSize(2);
        assertThat(output).doesNotContain(run.marker()).doesNotContainPattern("(?m)^\\s+at [a-z]")
                .doesNotContain("Exception in thread");
    }

    @Test
    @DisplayName("A drain that throws an Error: one line naming its class after the notice, no message or trace, status 143")
    void drainErrorOnSignal() throws Exception {
        assertReportedOnce(signalled(FailingStopPart.DRAIN, false), FailingStopPart.DrainError.class);
    }

    @Test
    @DisplayName("A termination that throws an Error: one line naming its class after the notice, no message or trace, status 143")
    void terminateErrorOnSignal() throws Exception {
        assertReportedOnce(signalled(FailingStopPart.TERMINATE, false), FailingStopPart.TerminateError.class);
    }

    @Test
    @DisplayName("A failing withdrawal and a failing termination: the line names the withdrawal's class only")
    void withdrawalIsTheFirstFailure() throws Exception {
        Run run = signalled(FailingStopPart.WITHDRAW + "," + FailingStopPart.TERMINATE, false);

        assertReportedOnce(run, FailingStopPart.WithdrawalError.class);
        assertThat(run.failureLines().getFirst()).doesNotContain("TerminateError");
    }

    @Test
    @DisplayName("A failing drain and a failing termination: the line names the drain's class only")
    void drainIsTheFirstOfTheCompositionFailures() throws Exception {
        Run run = signalled(FailingStopPart.DRAIN + "," + FailingStopPart.TERMINATE, false);

        assertReportedOnce(run, FailingStopPart.DrainError.class);
        assertThat(run.failureLines().getFirst()).doesNotContain("TerminateError");
    }

    @Test
    @DisplayName("With the log handlers removed before the hook runs the line is still written, and the process still exits")
    void lineSurvivesTheLoggingFrameworkShutdown() throws Exception {
        Run run = signalled(FailingStopPart.DRAIN, true);

        assertReportedOnce(run, FailingStopPart.DrainError.class);
    }

    @Test
    @DisplayName("When the serving thread performs the stop first there is exactly one line in total, and the exit is not completed")
    void servingThreadPerformsTheStop() throws Exception {
        String marker = "marker-" + UUID.randomUUID();
        try (LaunchedProcess process = LaunchedProcess.start(
                environment(FailingStopPart.DRAIN, marker, false, true), OPENED)) {
            int status = ServeSupport.awaitExitOrDestroy(process, 90);
            String output = process.output();

            assertThat(status).as(output).isEqualTo(IdentitySkuApplication.EXIT_NOT_COMPLETED);
            assertThat(output.split(java.util.regex.Pattern.quote(FAILED), -1)).as("occurrences of the line"
                    + System.lineSeparator() + output).hasSize(2);
            assertThat(output).contains(FAILED + FailingStopPart.DrainError.class.getName() + ")")
                    .doesNotContain(marker).doesNotContain("at eu.exeris.sku.identity.support.process");
        }
    }

    @Test
    @DisplayName("A fatal VM error from the drain is not reported as a stop failure: no stop-failure line, and the signal still ends the process with 143")
    void fatalErrorIsNotReportedAsAStopFailure() throws Exception {
        Run run = signalled(FailingStopPart.DRAIN_FATAL, false);

        assertThat(run.status()).as(run.output()).isEqualTo(SIGTERM_STATUS);
        assertThat(run.failureLines()).as(run.output()).isEmpty();
    }
}
