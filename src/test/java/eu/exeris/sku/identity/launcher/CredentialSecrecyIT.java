package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.launcher.BootstrapOwnerSupport.Run;
import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.TestConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A password that an operator puts into the database URL must not reach the output on any ending that is
 * reachable without a licence: a kernel that did not boot, a database that cannot be reached, a password
 * the database refuses, a role the service must not run as, and a URL the launcher cannot use. A URL that
 * carries a credential is refused before the driver is called, with SQLSTATE 08001; a URL that carries none
 * goes to the driver and the password of the settings must stay out of the output. Each value is generated
 * for the run. None of it needs a licence.
 */
@DisplayName("A password in the database URL is never printed")
class CredentialSecrecyIT {

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * What the URL carries. A credential in the authority or in the query is refused by the launcher before
     * the driver is called, so a run with such a URL ends as an unreachable database; a URL that carries no
     * credential reaches the driver and the run goes as far as the settings take it.
     */
    private enum Form {
        AUTHORITY(true) {
            @Override
            String apply(String url, String user, String password) {
                return url.replace("://", "://" + user + ":" + password + "@");
            }
        },
        CREDENTIAL_PARAMETER(true) {
            @Override
            String apply(String url, String user, String password) {
                return url + "?user=" + user + "&password=" + password;
            }
        },
        NO_CREDENTIAL(false) {
            @Override
            String apply(String url, String user, String password) {
                return url + "?ssl=false";
            }
        };

        private final boolean refused;

        Form(boolean refused) {
            this.refused = refused;
        }

        abstract String apply(String url, String user, String password);

        /** The status of a run that gets past the database connection when the driver is called. */
        int statusWhenConnected(int connected) {
            return refused ? IdentitySkuApplication.EXIT_UNAVAILABLE : connected;
        }

        /** The SQLSTATE the launcher logs when the database refuses the service role's password. */
        String stateOfWrongPassword() {
            return refused ? "08001" : "28P01";
        }
    }

    private static String random() {
        byte[] bytes = new byte[12];
        RANDOM.nextBytes(bytes);
        return "r" + HexFormat.of().formatHex(bytes);
    }

    private static Map<String, String> environment(PostgresSupport.Database database, String url) {
        Map<String, String> env = ServeSupport.environment(database, 0, InMemoryMembershipDirectory.class.getName());
        env.put("EXERIS_DATABASE_URL", url);
        return env;
    }

    private static Run serve(Map<String, String> env) throws Exception {
        try (LaunchedProcess process = LaunchedProcess.start(env)) {
            int status = ServeSupport.awaitExitOrDestroy(process, 90);
            return new Run(status, process.output());
        }
    }

    private static void assertAbsent(Run run, String... secrets) {
        for (String secret : secrets) {
            assertThat(run.output()).as("the output of a run that ended with " + run.status()).doesNotContain(secret);
        }
    }

    @Test
    @DisplayName("Without a licence the kernel does not boot, exits 70, and the password of the URL is not in the output")
    void noLicence() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        for (Form form : Form.values()) {
            Map<String, String> env = environment(database, form.apply(database.serviceUrl(),
                    database.serviceUser(), database.servicePassword()));
            env.put("EXERIS_HTTP_PORT", String.valueOf(LaunchedProcess.freePort()));

            Run run = serve(env);

            assertThat(run.status()).as(form + System.lineSeparator() + run.output())
                    .isEqualTo(form.statusWhenConnected(IdentitySkuApplication.EXIT_NOT_COMPLETED));
            if (form == Form.NO_CREDENTIAL) {
                assertThat(run.output()).as("the run reached the kernel's gate").contains("No license manifest found");
            } else {
                assertThat(run.output()).as("the driver was not called").contains("SQLSTATE 08001")
                        .doesNotContain("No license manifest found");
            }
            assertAbsent(run, database.servicePassword());
        }
    }

    @Test
    @DisplayName("An unreachable database exits 69 and the password of the URL is not in the output")
    void unreachableDatabase() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        for (Form form : Form.values()) {
            String password = random();
            String url = form.apply("jdbc:postgresql://127.0.0.1:" + LaunchedProcess.freePort() + "/identity",
                    "identity_service", password);
            Map<String, String> env = environment(database, url);
            env.put("EXERIS_DATABASE_PASSWORD", random());
            env.put("EXERIS_HTTP_PORT", String.valueOf(LaunchedProcess.freePort()));

            Run run = serve(env);

            assertThat(run.status()).as(form + System.lineSeparator() + run.output())
                    .isEqualTo(IdentitySkuApplication.EXIT_UNAVAILABLE);
            assertAbsent(run, password, env.get("EXERIS_DATABASE_PASSWORD"));
        }
    }

    @Test
    @DisplayName("A password the database refuses exits 69, as an unreachable database does, and neither password is in the output")
    void wrongDatabasePassword() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        for (Form form : Form.values()) {
            String inUrl = random();
            String inSetting = random();
            Map<String, String> env = environment(database, form.apply(database.serviceUrl(),
                    database.serviceUser(), inUrl));
            env.put("EXERIS_DATABASE_PASSWORD", inSetting);
            env.put("EXERIS_HTTP_PORT", String.valueOf(LaunchedProcess.freePort()));

            Run run = serve(env);

            assertThat(run.status()).as(form + System.lineSeparator() + run.output())
                    .isEqualTo(IdentitySkuApplication.EXIT_UNAVAILABLE);
            assertThat(run.output()).as("the SQLSTATE of the failure is what is logged")
                    .contains("SQLSTATE " + form.stateOfWrongPassword());
            assertAbsent(run, inUrl, inSetting);
        }
    }

    @Test
    @DisplayName("A service role that is a superuser exits 78 and the password of the URL is not in the output")
    void superuserRole() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        for (Form form : Form.values()) {
            Map<String, String> env = environment(database, form.apply(database.ownerUrl(),
                    database.ownerUser(), database.ownerPassword()));
            env.put("EXERIS_DATABASE_USER", database.ownerUser());
            env.put("EXERIS_DATABASE_PASSWORD", database.ownerPassword());
            env.put("EXERIS_HTTP_PORT", String.valueOf(LaunchedProcess.freePort()));

            Run run = serve(env);

            assertThat(run.status()).as(form + System.lineSeparator() + run.output())
                    .isEqualTo(form.statusWhenConnected(IdentitySkuApplication.EXIT_CONFIG));
            assertAbsent(run, database.ownerPassword());
        }
    }

    @Test
    @DisplayName("A URL that is not a jdbc:postgresql: URL exits 78 and its password is not in the output")
    void unusableUrl() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        String password = random();
        Map<String, String> env = environment(database, "postgresql://identity_service:" + password + "@db.example.test/identity");
        env.put("EXERIS_HTTP_PORT", String.valueOf(LaunchedProcess.freePort()));

        Run run = serve(env);

        assertThat(run.status()).as(run.output()).isEqualTo(IdentitySkuApplication.EXIT_CONFIG);
        assertAbsent(run, password);
    }

    @Test
    @DisplayName("bootstrap-owner without a licence exits 70 and the password of the URL is not in the output")
    void bootstrapOwnerNoLicence(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        for (Form form : Form.values()) {
            String ownerPassword = new String(TestConfig.randomPassword());
            Map<String, String> env = BootstrapOwnerSupport.environment(database,
                    BootstrapOwnerSupport.passwordFile(dir, ownerPassword));
            env.put("EXERIS_DATABASE_URL", form.apply(database.serviceUrl(), database.serviceUser(),
                    database.servicePassword()));

            Run run = BootstrapOwnerSupport.run(env);

            assertThat(run.status()).as(form + System.lineSeparator() + run.output())
                    .isEqualTo(form.statusWhenConnected(IdentitySkuApplication.EXIT_NOT_COMPLETED));
            if (form == Form.NO_CREDENTIAL) {
                assertThat(run.output()).contains("No license manifest found");
            } else {
                assertThat(run.output()).contains("SQLSTATE 08001").doesNotContain("No license manifest found");
            }
            assertAbsent(run, database.servicePassword(), ownerPassword);
            assertThat(BootstrapOwnerSupport.accounts(database)).isZero();
        }
    }

    @Test
    @DisplayName("bootstrap-owner with a wrong database password exits 69 and neither password is in the output")
    void bootstrapOwnerWrongPassword(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        for (Form form : Form.values()) {
            String inUrl = random();
            String inSetting = random();
            Map<String, String> env = BootstrapOwnerSupport.environment(database,
                    BootstrapOwnerSupport.passwordFile(dir, new String(TestConfig.randomPassword())));
            env.put("EXERIS_DATABASE_URL", form.apply(database.serviceUrl(), database.serviceUser(), inUrl));
            env.put("EXERIS_DATABASE_PASSWORD", inSetting);

            Run run = BootstrapOwnerSupport.run(env);

            assertThat(run.status()).as(form + System.lineSeparator() + run.output())
                    .isEqualTo(IdentitySkuApplication.EXIT_UNAVAILABLE);
            assertAbsent(run, inUrl, inSetting);
        }
    }
}
