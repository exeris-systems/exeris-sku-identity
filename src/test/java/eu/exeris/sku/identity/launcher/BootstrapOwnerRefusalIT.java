package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.RecordingInvitationDelivery;
import eu.exeris.sku.identity.support.RecordingNotificationDispatcher;
import eu.exeris.sku.identity.support.TestConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import static eu.exeris.sku.identity.launcher.BootstrapOwnerSupport.*;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every case in which the command must refuse before the kernel boots, so none needs a licence, plus the one
 * case where the kernel refuses to boot; each runs the real launcher in a process of its own. The refusals the
 * credential store decides inside the transaction are in {@link BootstrapOwnerProcessIT}.
 */
@DisplayName("bootstrap-owner refuses and changes nothing")
class BootstrapOwnerRefusalIT {

    private static final String PASSWORD_MIN = "EXERIS_CREDENTIALS_PASSWORD_MIN_LENGTH";
    private static final String PASSWORD_MAX = "EXERIS_CREDENTIALS_PASSWORD_MAX_LENGTH";

    /** One refusal: how the environment is spoiled, and the key the output must name. */
    private record Case(String name, String key, Consumer<Map<String, String>> spoil) {
    }

    private static void assertNoSecrets(String output, String... secrets) {
        assertThat(output).doesNotContain("eyJ");
        for (String secret : secrets) {
            assertThat(output).doesNotContain(secret);
        }
    }

    @TestFactory
    @DisplayName("Each configuration problem exits 78, names its key, and leaves rows and grants as they were")
    List<DynamicTest> configurationProblems(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        Path hostDirectory = Files.createDirectory(dir.resolve("host"));
        String password = new String(TestConfig.randomPassword());
        Path good = passwordFile(dir, password);
        UUID tenant = UUID.randomUUID();
        String inline = "inline-" + TestConfig.randomBase64(9);
        boolean posix = Files.getFileStore(dir).supportsFileAttributeView("posix");

        List<Case> cases = new ArrayList<>();
        cases.add(new Case("e-mail unset", EMAIL, env -> env.remove(EMAIL)));
        cases.add(new Case("password file unset", PASSWORD_FILE, env -> env.remove(PASSWORD_FILE)));
        cases.add(new Case("password file missing", PASSWORD_FILE,
                env -> env.put(PASSWORD_FILE, dir.resolve("absent").toString())));
        cases.add(new Case("password file is a directory", PASSWORD_FILE,
                env -> env.put(PASSWORD_FILE, dir.toString())));
        cases.add(new Case("password file is empty", PASSWORD_FILE, env -> {
            try {
                env.put(PASSWORD_FILE, passwordFile(dir, "").toString());
            } catch (java.io.IOException e) {
                throw new IllegalStateException(e);
            }
        }));
        cases.add(new Case("password file holds only newlines", PASSWORD_FILE, env -> {
            try {
                env.put(PASSWORD_FILE, passwordFile(dir, "\n\r\n\n").toString());
            } catch (java.io.IOException e) {
                throw new IllegalStateException(e);
            }
        }));
        if (posix) {
            for (String mode : new String[] {"rw-r-----", "rw----r--"}) {
                cases.add(new Case("password file mode " + mode, PASSWORD_FILE, env -> {
                    try {
                        env.put(PASSWORD_FILE, passwordFile(dir, password.getBytes(StandardCharsets.UTF_8), mode)
                                .toString());
                    } catch (java.io.IOException e) {
                        throw new IllegalStateException(e);
                    }
                }));
            }
        }
        cases.add(new Case("password shorter than the policy", PASSWORD_FILE, env -> env.put(PASSWORD_MIN, "60")));
        cases.add(new Case("password longer than the policy", PASSWORD_FILE, env -> {
            env.put(PASSWORD_MIN, "1");
            env.put(PASSWORD_MAX, "10");
        }));
        cases.add(new Case("password file is not UTF-8", PASSWORD_FILE, env -> {
            try {
                byte[] bad = new byte[30];
                java.util.Arrays.fill(bad, (byte) 'k');
                bad[10] = (byte) 0xFF;
                bad[11] = (byte) 0xFE;
                env.put(PASSWORD_FILE, passwordFile(dir, bad, "rw-------").toString());
            } catch (java.io.IOException e) {
                throw new IllegalStateException(e);
            }
        }));
        cases.add(new Case("inline password set together with a valid file", INLINE_PASSWORD,
                env -> env.put(INLINE_PASSWORD, inline)));
        cases.add(new Case("directory configured and tenant unset", TENANT, env -> env.remove(TENANT)));
        cases.add(new Case("tenant is not a UUID", TENANT, env -> env.put(TENANT, "tenant-" + TestConfig.randomBase64(3))));
        cases.add(new Case("environment unset", "EXERIS_ENVIRONMENT", env -> env.remove("EXERIS_ENVIRONMENT")));
        cases.add(new Case("environment unknown", "EXERIS_ENVIRONMENT", env -> env.put("EXERIS_ENVIRONMENT", "moonbase")));
        cases.add(new Case("service role is a superuser", "NOSUPERUSER", env -> {
            env.put("EXERIS_DATABASE_USER", database.ownerUser());
            env.put("EXERIS_DATABASE_PASSWORD", database.ownerPassword());
        }));

        List<DynamicTest> tests = new ArrayList<>();
        for (Case c : cases) {
            tests.add(DynamicTest.dynamicTest(c.name(), () -> {
                Map<String, String> env = environment(database, good);
                withDirectory(env, hostDirectory, tenant);
                c.spoil().accept(env);

                Run run = run(env);

                assertThat(run.status()).as(run.output()).isEqualTo(CONFIG);
                assertThat(run.output()).contains(c.key());
                assertThat(accounts(database)).isZero();
                assertThat(grants(hostDirectory)).isEmpty();
                assertNoSecrets(run.output(), password, database.servicePassword(), database.ownerPassword(), inline,
                        env.get(EMAIL) == null ? password : env.get(EMAIL));
            }));
        }
        tests.add(DynamicTest.dynamicTest("tenant set while no directory is configured", () -> {
            Map<String, String> env = environment(database, good);
            env.put(TENANT, tenant.toString());

            Run run = run(env);

            assertThat(run.status()).as(run.output()).isEqualTo(CONFIG);
            assertThat(run.output()).contains(TENANT);
            assertThat(accounts(database)).isZero();
            assertNoSecrets(run.output(), password, database.servicePassword());
        }));
        tests.add(DynamicTest.dynamicTest("a kernel environment property that disagrees with EXERIS_ENVIRONMENT", () -> {
            Map<String, String> env = environment(database, good);
            env.put("EXERIS_ENVIRONMENT", "staging");

            try (LaunchedProcess process = LaunchedProcess.start(env, List.of("-Dexeris.environment=production"),
                    "bootstrap-owner")) {
                int status = process.awaitExit(120);

                assertThat(status).as(process.output()).isEqualTo(CONFIG);
                assertThat(process.output()).contains("exeris.environment");
                assertThat(accounts(database)).isZero();
                assertNoSecrets(process.output(), password, database.servicePassword());
            }
        }));
        return tests;
    }

    @Test
    @DisplayName("Several problems are reported in one run, all named, with one exit 78")
    void severalProblemsAtOnce(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        String inline = "inline-" + TestConfig.randomBase64(9);
        Map<String, String> env = environment(database, passwordFile(dir, new String(TestConfig.randomPassword())));
        env.remove(EMAIL);
        env.put(PASSWORD_FILE, dir.resolve("absent").toString());
        env.put(INLINE_PASSWORD, inline);
        env.put(TENANT, UUID.randomUUID().toString());

        Run run = run(env);

        assertThat(run.status()).as(run.output()).isEqualTo(CONFIG);
        assertThat(run.output()).contains(EMAIL, PASSWORD_FILE, INLINE_PASSWORD, TENANT);
        assertThat(accounts(database)).isZero();
        assertNoSecrets(run.output(), inline, database.servicePassword());
    }

    @Test
    @DisplayName("A service role that bypasses row-level security exits 78 before the kernel boots, and nothing is written")
    void bypassRlsRole(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        String role = "bypass_" + TestConfig.randomBase64(6).replaceAll("[^A-Za-z0-9]", "x").toLowerCase();
        String rolePassword = "p" + TestConfig.randomBase64(12).replaceAll("[^A-Za-z0-9]", "x");
        try (Connection owner = database.owner(); Statement statement = owner.createStatement()) {
            statement.execute("CREATE ROLE " + role + " LOGIN PASSWORD '" + rolePassword + "' NOSUPERUSER BYPASSRLS");
            statement.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO " + role);
        }
        String password = new String(TestConfig.randomPassword());
        Map<String, String> env = environment(database, passwordFile(dir, password));
        env.put("EXERIS_DATABASE_USER", role);
        env.put("EXERIS_DATABASE_PASSWORD", rolePassword);

        Run run = run(env);

        assertThat(run.status()).as(run.output()).isEqualTo(CONFIG);
        assertThat(run.output()).contains("NOBYPASSRLS");
        assertThat(accounts(database)).isZero();
        assertNoSecrets(run.output(), password, rolePassword, env.get(EMAIL));
    }

    @Test
    @DisplayName("When configuration and the database are both wrong, configuration wins")
    void configurationBeatsDatabaseState(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.emptyDatabase();
        Map<String, String> env = environment(database, passwordFile(dir, new String(TestConfig.randomPassword())));
        env.remove(EMAIL);

        Run run = run(env);

        assertThat(run.status()).as(run.output()).isEqualTo(CONFIG);
        assertThat(tables(database)).isEmpty();
    }

    @Test
    @DisplayName("An unreachable database exits 69 and writes nothing")
    void unreachable(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        String password = new String(TestConfig.randomPassword());
        Map<String, String> env = environment(database, passwordFile(dir, password));
        env.put("EXERIS_DATABASE_URL", "jdbc:postgresql://127.0.0.1:" + LaunchedProcess.freePort() + "/identity");

        Run run = run(env);

        assertThat(run.status()).as(run.output()).isEqualTo(UNAVAILABLE);
        assertThat(accounts(database)).isZero();
        assertNoSecrets(run.output(), password, database.servicePassword(), env.get(EMAIL));
    }

    @Test
    @DisplayName("Any extra command-line argument, a password included, exits 64 and nothing is read or written")
    void extraArgument(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        Map<String, String> env = environment(database, passwordFile(dir, new String(TestConfig.randomPassword())));
        String asArgument = "arg-" + TestConfig.randomBase64(12);

        for (String[] arguments : new String[][] {{asArgument}, {"x", asArgument}}) {
            Run run = run(env, arguments);

            assertThat(run.status()).as(run.output()).isEqualTo(USAGE);
            assertThat(run.output()).contains("bootstrap-owner").doesNotContain(asArgument);
            assertThat(accounts(database)).isZero();
        }
    }

    @Test
    @DisplayName("A production environment with complete configuration and no licence manifest exits 70 and creates nothing")
    void productionWithoutManifest(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        String password = new String(TestConfig.randomPassword());
        Map<String, String> env = environment(database, passwordFile(dir, password));
        env.put("EXERIS_ENVIRONMENT", "production");
        env.put("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY", InMemoryMembershipDirectory.class.getName());
        env.put("EXERIS_IDENTITY_NOTIFICATION_DISPATCHER", RecordingNotificationDispatcher.class.getName());
        env.put("EXERIS_IDENTITY_INVITATION_DELIVERY", RecordingInvitationDelivery.class.getName());
        env.put(TENANT, UUID.randomUUID().toString());

        Run run = run(env);

        assertThat(run.status()).as(run.output()).isEqualTo(NOT_COMPLETED);
        assertThat(run.output()).contains("No license manifest found");
        assertThat(accounts(database)).isZero();
        assertNoSecrets(run.output(), password, database.servicePassword(), env.get(EMAIL));
    }
}
