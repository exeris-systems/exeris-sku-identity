package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A kernel that cannot boot, on a thread whose interrupt flag is set after the launcher's own checks. The
 * kernel's refusal is for a missing licence manifest, which has nothing to do with the interrupt, so none of
 * it needs a licence and none of it carries the kernel-boot tag.
 */
@DisplayName("serve whose kernel fails to boot while the thread is interrupted")
class ServeInterruptAtBootIT {

    @Test
    @DisplayName("A licence refusal is reported as the failure it is: status 70 and an error line, not a stop")
    void licenceRefusalIsNotMaskedByTheFlag() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        Map<String, String> env = ServeSupport.environment(database, LaunchedProcess.freePort(),
                InMemoryMembershipDirectory.class.getName());

        try (LaunchedProcess process = LaunchedProcess.startMain(InterruptAtBootMain.class.getName(), env,
                List.of("--enable-native-access=ALL-UNNAMED"))) {
            int exit = ServeSupport.awaitExitOrDestroy(process, 120);
            String output = process.output();

            assertThat(exit).as(output).isZero();
            assertThat(output).contains("RETURNED=true");
            assertThat(output).as("the status serve returned").contains("STATUS=" + IdentitySkuApplication.EXIT_NOT_COMPLETED);
            assertThat(output).contains("did not boot").doesNotContain("Asked to stop");
        }
    }
}
