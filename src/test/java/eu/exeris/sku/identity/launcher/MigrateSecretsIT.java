package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.launcher.BootstrapOwnerSupport.Run;
import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * No secret reaches the output of {@code migrate}, in any spelling, whichever way the migration ends. Each
 * case runs the launcher in a process of its own against a real PostgreSQL where a database is involved.
 */
@DisplayName("migrate: no secret reaches the output")
class MigrateSecretsIT {

    private static final int FAILED = IdentitySkuApplication.EXIT_MIGRATION_FAILED;
    private static final int CONFIG = IdentitySkuApplication.EXIT_CONFIG;

    private static Map<String, String> environment(String url, String user, String password) {
        Map<String, String> env = new HashMap<>();
        env.put("EXERIS_MIGRATE_DATABASE_URL", url);
        env.put("EXERIS_MIGRATE_DATABASE_USER", user);
        if (password != null) {
            env.put("EXERIS_MIGRATE_DATABASE_PASSWORD", password);
        }
        return env;
    }

    private static Run run(Map<String, String> env) throws Exception {
        try (LaunchedProcess process = LaunchedProcess.start(env, "migrate")) {
            int status = ServeSupport.awaitExitOrDestroy(process, 90);
            return new Run(status, process.output());
        }
    }

    private static void assertNone(Run run, String what, Map<String, String> secrets) {
        SecretForms.assertNoLeaks(run.output(), what + " (status " + run.status() + ")", secrets);
    }

    /** The output with the markers named, for a failure message that must not itself print a secret. */
    static String redacted(String output, Map<String, String> secrets) {
        String shown = output;
        for (Map.Entry<String, String> secret : secrets.entrySet()) {
            for (String form : SecretForms.forms(secret.getValue())) {
                shown = shown.replace(form, "<" + secret.getKey() + ">");
            }
        }
        return shown;
    }

    @Test
    @DisplayName("(a) A wrong migration password: the driver's refusal is logged with its SQLSTATE and neither password is in it")
    void wrongMigrationPassword() throws Exception {
        PostgresSupport.Database database = PostgresSupport.emptyDatabase();
        String wrong = SecretForms.markerWithSpecials();
        String service = SecretForms.marker();
        Map<String, String> env = environment(database.ownerUrl(), database.ownerUser(), wrong);
        env.put("EXERIS_DATABASE_PASSWORD", service);

        Run run = run(env);

        assertThat(run.status()).as(run.output()).isEqualTo(FAILED);
        assertThat(run.output()).contains("SQLSTATE 28P01");
        assertNone(run, "wrong migration password", Map.of("MIGRATION", wrong, "SERVICE", service));
    }

    @Test
    @DisplayName("(a) The same with the password in a file that ends in a line break")
    void wrongMigrationPasswordFromFile(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.emptyDatabase();
        String wrong = SecretForms.marker();
        Path file = Files.writeString(dir.resolve("migration-password"), wrong + "\n");
        Map<String, String> env = environment(database.ownerUrl(), database.ownerUser(), null);
        env.put("EXERIS_MIGRATE_DATABASE_PASSWORD_FILE", file.toString());
        String service = SecretForms.marker();
        Path serviceFile = Files.writeString(dir.resolve("service-password"), service + "\r\n");
        env.put("EXERIS_DATABASE_PASSWORD_FILE", serviceFile.toString());

        Run run = run(env);

        assertThat(run.status()).as(run.output()).isEqualTo(FAILED);
        assertThat(run.output()).contains("SQLSTATE 28P01");
        assertNone(run, "wrong migration password from a file", Map.of("MIGRATION", wrong, "SERVICE", service));
    }

    /** The ways a credential can sit in a URL, as {@code url -> url with the credential}. */
    private static Map<String, String> urlsCarrying(String base, String user, String credential) {
        Map<String, String> urls = new LinkedHashMap<>();
        urls.put("authority", base.replace("://", "://" + user + ":" + credential + "@"));
        urls.put("query", base + "?user=" + user + "&password=" + credential);
        urls.put("query after other parameters", base + "?ssl=false&password=" + credential + "&user=" + user);
        urls.put("semicolon", base + ";password=" + credential);
        urls.put("semicolon after a query", base + "?ssl=false;password=" + credential);
        return urls;
    }

    @Test
    @DisplayName("(b) A password carried in the URL, in its authority, a query parameter or after a semicolon, is never in the output; the SQLSTATE is")
    void passwordInTheUrl() throws Exception {
        PostgresSupport.Database database = PostgresSupport.emptyDatabase();
        String credential = SecretForms.marker();
        for (Map.Entry<String, String> url : urlsCarrying(database.ownerUrl(), database.ownerUser(), credential)
                .entrySet()) {
            String configured = SecretForms.marker();
            Map<String, String> env = environment(url.getValue(), database.ownerUser(), configured);

            Run run = run(env);

            assertThat(run.status()).as(url.getKey() + System.lineSeparator()
                    + redacted(run.output(), Map.of("URL", credential, "MIGRATION", configured))).isEqualTo(FAILED);
            assertThat(run.output()).as(url.getKey()).contains("SQLSTATE");
            assertNone(run, "URL credential in the " + url.getKey(), Map.of("URL", credential,
                    "MIGRATION", configured));
        }
    }

    @Test
    @DisplayName("(b) The same URLs when the URL's credential is also the configured migration password")
    void passwordInTheUrlAndConfigured() throws Exception {
        PostgresSupport.Database database = PostgresSupport.emptyDatabase();
        String credential = SecretForms.marker();
        for (Map.Entry<String, String> url : urlsCarrying(database.ownerUrl(), database.ownerUser(), credential)
                .entrySet()) {
            Run run = run(environment(url.getValue(), database.ownerUser(), credential));

            assertThat(run.status()).as(url.getKey() + System.lineSeparator() + run.output()).isEqualTo(FAILED);
            assertNone(run, "URL credential in the " + url.getKey(), Map.of("CREDENTIAL", credential));
        }
    }

    @Test
    @DisplayName("(c) An unreachable host: exits 1 with the SQLSTATE and no password, also when the URL carries one")
    void unreachableHost() throws Exception {
        String inUrl = SecretForms.marker();
        String configured = SecretForms.markerWithSpecials();
        for (Map.Entry<String, String> url : urlsCarrying("jdbc:postgresql://127.0.0.1:" + LaunchedProcess.freePort()
                + "/identity", "identity_owner", inUrl).entrySet()) {
            Run run = run(environment(url.getValue(), "identity_owner", configured));

            assertThat(run.status()).as(url.getKey() + System.lineSeparator() + run.output()).isEqualTo(FAILED);
            assertThat(run.output()).as(url.getKey()).contains("SQLSTATE");
            assertNone(run, "unreachable host, URL with the credential in the " + url.getKey(),
                    Map.of("URL", inUrl, "MIGRATION", configured));
        }
    }

    @Test
    @DisplayName("(d) A URL the driver cannot parse, so no connection is ever tried: exits 1, the password is in neither the inline nor the file form of the output")
    void malformedUrl(@TempDir Path dir) throws Exception {
        String inUrl = SecretForms.marker();
        String configured = SecretForms.marker();
        Path file = Files.writeString(dir.resolve("migration-password"), configured + "\n");
        java.util.List<String> leaks = new java.util.ArrayList<>();
        for (String url : new String[]{
                "jdbc:postgresql://u:" + inUrl + "@host:notaport/db",
                "jdbc:postgresql://u:" + inUrl + "@127.0.0.1:" + 1 + "/db",
                "jdbc:postgresql://u:" + inUrl + "@[::1/db",
                "jdbc:postgresql://host:99999999/db?password=" + inUrl,
                "jdbc:postgresql:///db?user=u&password=" + inUrl + "&sslmode=%zz",
                "jdbc:postgresql://u:" + inUrl + "@/db?loginTimeout=abc"}) {
            for (boolean fromFile : new boolean[]{false, true}) {
                Map<String, String> env = environment(url, "u", fromFile ? null : configured);
                if (fromFile) {
                    env.put("EXERIS_MIGRATE_DATABASE_PASSWORD_FILE", file.toString());
                }

                Run run = run(env);

                assertThat(run.status()).as(url.replace(inUrl, "<URL>") + " from a file: " + fromFile)
                        .isIn(FAILED, CONFIG);
                for (Map.Entry<String, String> secret : Map.of("URL", inUrl, "MIGRATION", configured).entrySet()) {
                    SecretForms.leaks(run.output(), secret.getKey(), secret.getValue())
                            .forEach(line -> leaks.add(url.replace(inUrl, "<URL>") + " / "
                                    + (fromFile ? "password in a file" : "password inline") + ": " + line));
                }
            }
        }
        assertThat(leaks).as("lines of the output that hold a secret").isEmpty();
    }

    @Test
    @DisplayName("(d) A URL with credentials in its authority and no port, which the driver reads as a host and a port: the driver's own log line does not carry the credential")
    void authorityWithoutPort() throws Exception {
        String inUrl = SecretForms.marker();
        String configured = SecretForms.marker();

        Run run = run(environment("jdbc:postgresql://u:" + inUrl + "@127.0.0.1/db", "u", configured));

        assertThat(run.status()).isEqualTo(FAILED);
        assertNone(run, "credential in an authority without a port", Map.of("URL", inUrl, "MIGRATION", configured));
    }

    @Test
    @DisplayName("(d) A URL that is not a jdbc:postgresql: URL is refused with status 78 without quoting it")
    void notAJdbcUrl(@TempDir Path dir) throws Exception {
        String inUrl = SecretForms.marker();
        String configured = SecretForms.marker();
        Path file = Files.writeString(dir.resolve("migration-password"), configured);
        for (boolean fromFile : new boolean[]{false, true}) {
            Map<String, String> env = environment("postgresql://u:" + inUrl + "@db.example.test/identity", "u",
                    fromFile ? null : configured);
            if (fromFile) {
                env.put("EXERIS_MIGRATE_DATABASE_PASSWORD_FILE", file.toString());
            }

            Run run = run(env);

            assertThat(run.status()).as(run.output()).isEqualTo(CONFIG);
            assertThat(run.output()).contains("EXERIS_MIGRATE_DATABASE_URL");
            assertNone(run, "URL that is not a JDBC URL", Map.of("URL", inUrl, "MIGRATION", configured));
        }
    }

    @Test
    @DisplayName("(e) A migration statement that fails with a message quoting the service password: the message is logged with the SQLSTATE and the quoted value withheld")
    void statementEchoesTheServicePassword() throws Exception {
        PostgresSupport.Database database = PostgresSupport.emptyDatabase();
        // A role that does not exist is named in the database's error, and a lower-case word is a legal role
        // name, so a service password of that shape is echoed by the statement that fails on it.
        String echoed = SecretForms.lowerCaseMarker();
        Map<String, String> env = environment(database.ownerUrl(), database.ownerUser(), database.ownerPassword());
        env.put("EXERIS_MIGRATE_SERVICE_ROLE", echoed);
        env.put("EXERIS_DATABASE_PASSWORD", echoed);

        Run run = run(env);

        assertEchoed(run, "service password", echoed);
    }

    @Test
    @DisplayName("(e) The same when the quoted value is the migration password")
    void statementEchoesTheMigrationPassword() throws Exception {
        PostgresSupport.Database database = PostgresSupport.emptyDatabase();
        String echoed = SecretForms.lowerCaseMarker();
        try (var owner = database.owner(); var statement = owner.createStatement()) {
            statement.execute("CREATE ROLE migrator_" + echoed + " LOGIN SUPERUSER PASSWORD '" + echoed + "'");
        }
        Map<String, String> env = environment(database.ownerUrl(), "migrator_" + echoed, echoed);
        env.put("EXERIS_MIGRATE_SERVICE_ROLE", echoed);

        Run run = run(env);

        assertEchoed(run, "migration password", echoed);
    }

    private static void assertEchoed(Run run, String what, String echoed) {
        assertThat(run.status()).as(what + System.lineSeparator() + redacted(run.output(), Map.of("ECHOED", echoed)))
                .isEqualTo(FAILED);
        assertThat(run.output()).as("the failure is the missing role, which the database names")
                .contains("SQLSTATE 42704").contains("<withheld>");
        assertNone(run, "role name equal to the " + what, Map.of("ECHOED", echoed));
    }

    @Test
    @DisplayName("Success logs the count of migrations and no secret")
    void successHoldsNoSecret() throws Exception {
        PostgresSupport.Database database = PostgresSupport.emptyDatabase();
        String service = SecretForms.marker();
        Map<String, String> env = environment(database.ownerUrl(), database.ownerUser(), database.ownerPassword());
        env.put("EXERIS_DATABASE_PASSWORD", service);

        Run run = run(env);

        assertThat(run.status()).as(run.output()).isZero();
        assertThat(run.output()).as("migrate never boots the kernel").doesNotContain("Booting Exeris Kernel");
        assertNone(run, "success", Map.of("SERVICE", service, "MIGRATION", database.ownerPassword()));
    }

    @Test
    @DisplayName("Settings missing: the refusal names the settings and no value, with both passwords set")
    void incompleteSettings() throws Exception {
        String migration = SecretForms.marker();
        String service = SecretForms.marker();
        Map<String, String> env = new HashMap<>();
        env.put("EXERIS_MIGRATE_DATABASE_PASSWORD", migration);
        env.put("EXERIS_DATABASE_PASSWORD", service);

        Run run = run(env);

        assertThat(run.status()).isEqualTo(CONFIG);
        assertNone(run, "incomplete settings", Map.of("MIGRATION", migration, "SERVICE", service));
    }

    @Test
    @DisplayName("An unreadable password file and a password file next to an inline password are refused without a value")
    void passwordFileProblems(@TempDir Path dir) throws IOException, Exception {
        String inline = SecretForms.marker();
        String inFile = SecretForms.marker();
        Path file = Files.writeString(dir.resolve("p"), inFile);
        PostgresSupport.Database database = PostgresSupport.emptyDatabase();
        Map<String, String> both = environment(database.ownerUrl(), database.ownerUser(), inline);
        both.put("EXERIS_MIGRATE_DATABASE_PASSWORD_FILE", file.toString());

        Run run = run(both);

        assertThat(run.status()).as(run.output()).isEqualTo(CONFIG);
        assertNone(run, "inline and file together", Map.of("INLINE", inline, "FILE", inFile));
    }
}
