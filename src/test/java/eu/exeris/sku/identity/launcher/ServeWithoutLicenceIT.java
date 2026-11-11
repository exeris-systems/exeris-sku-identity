package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.TestConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A serve whose kernel does not boot because no licence manifest is given. None of it needs a licence,
 * so none of it carries the kernel-boot tag.
 */
@DisplayName("serve without a licence manifest")
class ServeWithoutLicenceIT {

    private static final long BOUND_SECONDS = 90;

    private static Map<String, String> environment(int port, Map<String, String> identity) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        Map<String, String> env = LaunchedProcess.serviceEnvironment(database, port, identity);
        env.put("EXERIS_ENVIRONMENT", "development");
        env.put("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY", InMemoryMembershipDirectory.class.getName());
        return env;
    }

    @Test
    @DisplayName("Exits not completed, reports the gate's message once as an error and no exception, and never listens")
    void kernelDoesNotBoot() throws Exception {
        Map<String, String> identity = TestConfig.env();
        int port = LaunchedProcess.freePort();
        Map<String, String> env = environment(port, identity);
        String databasePassword = env.get("EXERIS_DATABASE_PASSWORD");

        try (LaunchedProcess process = LaunchedProcess.start(env)) {
            boolean listenedWhileRunning = false;
            long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(BOUND_SECONDS);
            while (process.isAlive() && System.nanoTime() < deadline) {
                listenedWhileRunning |= ServeSupport.accepts(port);
                Thread.sleep(50);
            }
            int status = ServeSupport.awaitExitOrDestroy(process, 5);
            String output = process.output();

            assertThat(status).as(output).isEqualTo(IdentitySkuApplication.EXIT_NOT_COMPLETED);
            assertThat(output.lines().filter(line -> line.contains("No license manifest found")))
                    .as("the gate's message on an error line that says the kernel did not boot")
                    .anySatisfy(line -> assertThat(line).containsIgnoringCase("did not boot")
                            .contains("exeris-sku-identity")
                            .containsPattern("ERROR|SEVERE"));
            assertThat(output).doesNotContain("Exception in thread \"main\"")
                    .doesNotContain("Kernel boot failed")
                    .doesNotContain("IllegalStateException");
            assertThat(output).doesNotContain(databasePassword);
            for (String name : new String[]{"EXERIS_TOKEN_ISSUER_KEKS", "EXERIS_MFA_TOTP_KEKS",
                    "EXERIS_MFA_TOTP_PEPPER", "EXERIS_FEDERATED_LOGIN_STATE_KEYS"}) {
                String material = identity.get(name);
                assertThat(output).as(name).doesNotContain(material.substring(material.indexOf(':') + 1));
            }
            assertThat(listenedWhileRunning).as("something listened on the port while serve ran").isFalse();
            assertThat(ServeSupport.accepts(port)).as("the port after serve exited").isFalse();
        }
    }
}
