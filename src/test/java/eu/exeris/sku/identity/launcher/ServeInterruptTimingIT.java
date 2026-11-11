package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
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
 * An interrupt of the serving thread at each point before the service serves, and while it serves. The call
 * runs in a JVM of its own, see {@link InterruptTimingMain}. In every case the call returns the status of a
 * stop on request, the thread's interrupt flag is still set when it returns, and no failure is reported.
 */
@Tag("kernel-boot")
@DisplayName("serve interrupted at each point")
class ServeInterruptTimingIT {

    private static String run(String timing, String directory, Map<String, String> extra, int[] portOut) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        int port = LaunchedProcess.freePort();
        portOut[0] = port;
        Map<String, String> env = ServeSupport.licensedEnvironment(database, port, directory);
        env.put(InterruptTimingMain.MODE, timing);
        env.putAll(extra);
        try (LaunchedProcess process = LaunchedProcess.startMain(InterruptTimingMain.class.getName(), env,
                List.of("--enable-native-access=ALL-UNNAMED"))) {
            int exit = ServeSupport.awaitExitOrDestroy(process, 180);
            String output = process.output();
            assertThat(exit).as(output).isZero();
            return output;
        }
    }

    private static void assertStoppedOnRequest(String output, int port) {
        assertThat(output).contains("RETURNED=true").as(output).contains("STATUS=0").contains("FLAG=true");
        assertThat(output).doesNotContain("Stopping Identity failed").doesNotContain("Identity failed")
                .doesNotContain("draining a capability failed").doesNotContain("terminating ");
        assertThat(output).as("threads left after they were given time to end").contains("SETTLED=[]");
        assertThat(ServeSupport.accepts(port)).as("the port after serve returned").isFalse();
    }

    /** The password encoder the callback builds first refuses to be built on an interrupted thread. */
    @Test
    @DisplayName("As soon as the kernel calls back: status 0, never served, health never 200, the flag still set")
    void atTheKernelCallback() throws Exception {
        int[] port = new int[1];
        String output = run(InterruptTimingMain.CALLBACK, InMemoryMembershipDirectory.class.getName(), Map.of(), port);

        assertThat(output).contains("INTERRUPTED_IN=callback");
        assertStoppedOnRequest(output, port[0]);
        assertThat(output).doesNotContain(ServeSupport.RUNNING_LINE).contains("EVER_HEALTHY=false");
    }

    /** The kernel refuses to boot on an interrupted thread; that refusal is a stop, not a failure. */
    @Test
    @DisplayName("Before the call: status 0, never served, health never 200, the flag still set")
    void beforeTheCall() throws Exception {
        int[] port = new int[1];
        String output = run(InterruptTimingMain.ENTRY, InMemoryMembershipDirectory.class.getName(), Map.of(), port);

        assertStoppedOnRequest(output, port[0]);
        assertThat(output).doesNotContain(ServeSupport.RUNNING_LINE).contains("EVER_HEALTHY=false");
    }

    @Test
    @DisplayName("During the join of the transactional executor: status 0, never served, health never 200, the flag still set")
    void duringTheJoin() throws Exception {
        int[] port = new int[1];
        String output = run(InterruptTimingMain.JOIN, ThrowingOnJoinPart.class.getName(),
                Map.of(ThrowingOnJoinPart.KIND_VARIABLE, ThrowingOnJoinPart.PARK), port);

        assertThat(output).contains("INTERRUPTED_IN=parked");
        assertStoppedOnRequest(output, port[0]);
        assertThat(output).doesNotContain(ServeSupport.RUNNING_LINE).contains("EVER_HEALTHY=false");
    }

    @Test
    @DisplayName("While the composition starts: status 0, never logged as running, the flag still set")
    void duringTheStart() throws Exception {
        int[] port = new int[1];
        String output = run(InterruptTimingMain.START, InterruptingPart.class.getName(),
                Map.of(InterruptingPart.MODE_VARIABLE, InterruptingPart.START), port);

        assertThat(output).as("the interrupt was delivered inside tryStart").contains("INTERRUPTED_IN=tryStart");
        assertStoppedOnRequest(output, port[0]);
        assertThat(output).doesNotContain(ServeSupport.RUNNING_LINE).contains("EVER_HEALTHY=false");
    }

    @Test
    @DisplayName("Just before the running line: status 0, the line never logged, the flag still set")
    void justBeforeTheRunningLine() throws Exception {
        int[] port = new int[1];
        String output = run(InterruptTimingMain.SERVE, InterruptingPart.class.getName(),
                Map.of(InterruptingPart.MODE_VARIABLE, InterruptingPart.SERVE), port);

        assertThat(output).as("the interrupt was delivered while the thread waited to serve").contains(InterruptingPart.INTERRUPTED_LINE);
        assertStoppedOnRequest(output, port[0]);
        assertThat(output).doesNotContain(ServeSupport.RUNNING_LINE);
    }

    @Test
    @DisplayName("While the service is healthy and serving: status 0, a normal drain, the flag still set")
    void whileServing() throws Exception {
        int[] port = new int[1];
        String output = run(InterruptTimingMain.HEALTHY, InMemoryMembershipDirectory.class.getName(), Map.of(), port);

        assertThat(output).contains("INTERRUPTED_WHEN=healthy true").contains(ServeSupport.RUNNING_LINE);
        assertStoppedOnRequest(output, port[0]);
    }
}
