package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.process.ThrowingOnJoinPart;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code serve} called as a method on a thread that is interrupted while a host part is still parked before
 * the composition starts. The call runs in a JVM of its own, see {@link InProcessInterruptedServeMain}.
 */
@Tag("kernel-boot")
@DisplayName("serve interrupted before the composition starts")
class ServeInterruptBeforeStartIT {

    @Test
    @DisplayName("Returns 0, never served, answered /health 200 to nobody, and leaves no non-daemon thread behind")
    void interruptWhileAHostPartIsParked() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        int port = LaunchedProcess.freePort();
        Map<String, String> env = ServeSupport.licensedEnvironment(database, port, ThrowingOnJoinPart.class.getName());
        env.put(ThrowingOnJoinPart.KIND_VARIABLE, ThrowingOnJoinPart.PARK);

        try (LaunchedProcess process = LaunchedProcess.startMain(InProcessInterruptedServeMain.class.getName(), env,
                List.of("--enable-native-access=ALL-UNNAMED"))) {
            int exit = ServeSupport.awaitExitOrDestroy(process, 180);
            String output = process.output();

            assertThat(exit).as(output).isZero();
            assertThat(output).contains("RETURNED=true").doesNotContain("NEVER_PARKED");
            assertThat(output).as("the status serve returned").contains("STATUS=0");
            assertThat(output).as("the service never ran").doesNotContain(ServeSupport.RUNNING_LINE);
            assertThat(output).as("health answered 200 at some point").contains("EVER_HEALTHY=false");
            assertThat(output).doesNotContain("Stopping Identity failed").doesNotContain("Identity failed");
            assertThat(output).as("threads left after they were given time to end").contains("SETTLED=[]");
            assertThat(ServeSupport.accepts(port)).as("the port after serve returned").isFalse();
        }
    }
}
