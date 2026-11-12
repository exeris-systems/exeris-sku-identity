package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code serve} called as a method, as an embedding host would, on a thread that is then interrupted. The call
 * runs in a JVM of its own because the kernel reads its licence manifest from the process environment, which
 * the test JVM must not have; {@link InProcessServeMain} reports what the call returned.
 */
@Tag("kernel-boot")
@DisplayName("serve called in-process")
class ServeInProcessIT {

    @Test
    @DisplayName("An interrupted serve returns 0 and leaves no non-daemon thread that was not there before")
    void interruptReturnsZeroAndLeavesNoThread() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        int port = LaunchedProcess.freePort();
        Map<String, String> env = ServeSupport.licensedEnvironment(database, port,
                InMemoryMembershipDirectory.class.getName());

        try (LaunchedProcess process = LaunchedProcess.startMain(InProcessServeMain.class.getName(), env,
                List.of("--enable-native-access=ALL-UNNAMED"))) {
            int exit = ServeSupport.awaitExitOrDestroy(process, 180);
            String output = process.output();

            assertThat(exit).as(output).isZero();
            assertThat(output).contains("RETURNED=true").contains("STATUS=0").doesNotContain("NEVER_HEALTHY");
            assertThat(output).as("threads left by the call, after they were given time to end")
                    .contains("SETTLED=[]");
            assertThat(output).as("threads left at the moment the call returned").contains("LEFTOVER=[]");
            assertThat(output).doesNotContain("Stopping Identity failed");
            assertThat(ServeSupport.accepts(port)).as("the port after serve returned").isFalse();
        }
    }
}
