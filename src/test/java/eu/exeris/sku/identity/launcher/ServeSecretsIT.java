package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.launcher.BootstrapOwnerSupport.Run;
import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.TestConfig;
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
 * No secret reaches the output of {@code serve} on an ending reached before the kernel boots: a refused
 * configuration and a database that cannot be used. Each case runs the launcher in a process of its own.
 */
@DisplayName("serve: no secret reaches the output before the kernel boots")
class ServeSecretsIT {

    /** An environment that is complete and points at a database nobody listens on. */
    private static Map<String, String> unreachable() throws IOException {
        PostgresSupport.Database nowhere = new PostgresSupport.Database("jdbc:postgresql://127.0.0.1:"
                + LaunchedProcess.freePort() + "/identity", "owner", "unused", "jdbc:postgresql://127.0.0.1:"
                + LaunchedProcess.freePort() + "/identity", "identity_service", "unused-service-password");
        Map<String, String> env = LaunchedProcess.serviceEnvironment(nowhere, LaunchedProcess.freePort(),
                TestConfig.env());
        env.put("EXERIS_ENVIRONMENT", "development");
        env.put("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY", InMemoryMembershipDirectory.class.getName());
        return env;
    }

    private static Run serve(Map<String, String> env) throws Exception {
        try (LaunchedProcess process = LaunchedProcess.start(env)) {
            int status = ServeSupport.awaitExitOrDestroy(process, 90);
            return new Run(status, process.output());
        }
    }

    private static Map<String, String> markers(String... names) {
        Map<String, String> markers = new LinkedHashMap<>();
        for (String name : names) {
            markers.put(name, SecretForms.marker());
        }
        return markers;
    }

    @Test
    @DisplayName("(a) A refused configuration names each setting and quotes none of the values: a CORS origin with user information, a bad port, a bad duration, a proxy list, a header, an environment, a host part and a pool size")
    void configurationRefusalQuotesNoValue() throws Exception {
        Map<String, String> m = markers("ORIGIN", "ORIGIN_ENTRY", "PORT", "BODY", "TTL", "MAX_TTL", "JWT_ISSUER",
                "JWT_AUDIENCE", "PROXIES", "HEADER", "MIN_LENGTH", "POOL", "HOST_PART", "ISSUER_TTL", "ARGON",
                "LOCKOUT");
        Map<String, String> env = unreachable();
        env.put("EXERIS_CORS_ALLOWED_ORIGINS", "https://u:" + m.get("ORIGIN") + "@h.example.test," + m.get("ORIGIN_ENTRY"));
        env.put("EXERIS_HTTP_PORT", m.get("PORT"));
        env.put("EXERIS_HTTP_MAX_REQUEST_BODY_BYTES", m.get("BODY"));
        env.put("EXERIS_MFA_TOTP_CHALLENGE_TTL", m.get("TTL"));
        env.put("EXERIS_MFA_TOTP_CHALLENGE_MAX_TTL", "PT" + m.get("MAX_TTL"));
        env.put("EXERIS_JWT_ISSUER", m.get("JWT_ISSUER"));
        env.put("EXERIS_JWT_AUDIENCE", m.get("JWT_AUDIENCE"));
        env.put("EXERIS_RATELIMIT_TRUSTED_PROXIES", m.get("PROXIES"));
        env.put("EXERIS_RATELIMIT_FORWARDED_HEADER", m.get("HEADER") + " bad");
        env.put("EXERIS_CREDENTIALS_PASSWORD_MIN_LENGTH", m.get("MIN_LENGTH"));
        env.put("EXERIS_DATABASE_MAX_POOL_SIZE", m.get("POOL"));
        env.put("EXERIS_IDENTITY_NOTIFICATION_DISPATCHER", m.get("HOST_PART"));
        env.put("EXERIS_TOKEN_ISSUER_TOKEN_TTL", m.get("ISSUER_TTL"));
        env.put("EXERIS_PASSWORD_ARGON2_MEMORY_KIB", m.get("ARGON"));
        env.put("EXERIS_CREDENTIALS_LOCKOUT_MAX_ATTEMPTS", m.get("LOCKOUT"));

        Run run = serve(env);

        assertThat(run.status()).as(run.output()).isEqualTo(IdentitySkuApplication.EXIT_CONFIG);
        assertThat(run.output()).contains("EXERIS_HTTP_PORT").contains("EXERIS_CORS_ALLOWED_ORIGINS");
        SecretForms.assertNoLeaks(run.output(), "refused configuration", m);
    }

    @Test
    @DisplayName("(a) A port or a whole number outside its range is refused without quoting the number")
    void numericValueOutOfRange() throws Exception {
        String number = SecretForms.numericMarker();
        Map<String, String> env = unreachable();
        env.put("EXERIS_HTTP_PORT", number);
        env.put("EXERIS_CREDENTIALS_LOCKOUT_MAX_ATTEMPTS", number);
        env.put("EXERIS_RATELIMIT_MAX_KEYS", number);

        Run run = serve(env);

        assertThat(run.status()).isEqualTo(IdentitySkuApplication.EXIT_CONFIG);
        SecretForms.assertNoLeaks(run.output(), "a number outside its range", Map.of("NUMBER", number));
    }

    @Test
    @DisplayName("(a) A numeric database password that is also pasted into a numeric setting is withheld, because the launcher knows it")
    void numericDatabasePasswordInASetting() throws Exception {
        String number = SecretForms.numericMarker();
        Map<String, String> env = unreachable();
        env.put("EXERIS_DATABASE_PASSWORD", number);
        env.put("EXERIS_HTTP_PORT", number);

        Run run = serve(env);

        assertThat(run.status()).isEqualTo(IdentitySkuApplication.EXIT_CONFIG);
        SecretForms.assertNoLeaks(run.output(), "the database password in a port", Map.of("PASSWORD", number));
    }

    @Test
    @DisplayName("(a) With the service password set as a value, as a file with a line break, and a bad port, nothing of either is printed")
    void passwordKnownWhenConfigurationFails(@TempDir Path dir) throws Exception {
        String inline = SecretForms.markerWithSpecials();
        String inFile = SecretForms.marker();
        Path file = Files.writeString(dir.resolve("p"), inFile + "\n");
        for (boolean fromFile : new boolean[]{false, true}) {
            Map<String, String> env = unreachable();
            env.remove("EXERIS_DATABASE_PASSWORD");
            if (fromFile) {
                env.put("EXERIS_DATABASE_PASSWORD_FILE", file.toString());
                env.put("EXERIS_HTTP_PORT", inFile + "x");
                env.put("EXERIS_JWT_ISSUER", "issuer-" + inFile);
            } else {
                env.put("EXERIS_DATABASE_PASSWORD", inline);
                env.put("EXERIS_HTTP_PORT", inline);
                env.put("EXERIS_JWT_ISSUER", "issuer-" + inline);
            }

            Run run = serve(env);

            assertThat(run.status()).isEqualTo(IdentitySkuApplication.EXIT_CONFIG);
            SecretForms.assertNoLeaks(run.output(), fromFile ? "password from a file" : "inline password",
                    Map.of("PASSWORD", fromFile ? inFile : inline));
        }
    }

    // --- the identity configuration file -----------------------------------------------------------------

    @Test
    @DisplayName("A setting given in the identity configuration file is refused or used without being printed, and a database password in the file is an unknown setting")
    void valuesFromTheConfigurationFile(@TempDir Path dir) throws Exception {
        Map<String, String> m = markers("DB_IN_FILE", "PORT_IN_FILE", "ORIGIN_IN_FILE", "TTL_IN_FILE");
        Path file = Files.writeString(dir.resolve("identity.properties"),
                "EXERIS_DATABASE_PASSWORD=" + m.get("DB_IN_FILE") + "\n"
                        + "EXERIS_HTTP_PORT=" + m.get("PORT_IN_FILE") + "\n"
                        + "EXERIS_CORS_ALLOWED_ORIGINS=https://u:" + m.get("ORIGIN_IN_FILE") + "@h.example.test\n"
                        + "EXERIS_MFA_TOTP_CHALLENGE_TTL=" + m.get("TTL_IN_FILE") + "\n");
        Map<String, String> env = unreachable();
        env.put("EXERIS_IDENTITY_CONFIG", file.toString());
        env.remove("EXERIS_HTTP_PORT");

        Run run = serve(env);

        assertThat(run.status()).as(run.output()).isEqualTo(IdentitySkuApplication.EXIT_CONFIG);
        assertThat(run.output()).as("a database password in the file is not a setting of the file")
                .contains("unknown setting: EXERIS_DATABASE_PASSWORD");
        SecretForms.assertNoLeaks(run.output(), "values read from the configuration file", m);
    }

    @Test
    @DisplayName("A line of the configuration file that is not a setting is refused without being printed")
    void lineThatIsNotASetting(@TempDir Path dir) throws Exception {
        String pasted = SecretForms.marker();
        Path file = Files.writeString(dir.resolve("identity.properties"), pasted + "\n");
        Map<String, String> env = unreachable();
        env.put("EXERIS_IDENTITY_CONFIG", file.toString());

        Run run = serve(env);

        assertThat(run.status()).isEqualTo(IdentitySkuApplication.EXIT_CONFIG);
        SecretForms.assertNoLeaks(run.output(), "a pasted value as a key of the file", Map.of("PASTED", pasted));
    }

    @Test
    @DisplayName("A keyring or pepper file setting that holds the value instead of a path is refused without being printed")
    void valueWhereAPathBelongs() throws Exception {
        Map<String, String> m = markers("TOKEN_KEKS", "MFA_KEKS", "PEPPER", "FEDERATED");
        Map<String, String> env = unreachable();
        for (String key : new String[]{"EXERIS_TOKEN_ISSUER_KEKS", "EXERIS_MFA_TOTP_KEKS", "EXERIS_MFA_TOTP_PEPPER",
                "EXERIS_FEDERATED_LOGIN_STATE_KEYS"}) {
            env.remove(key);
        }
        env.put("EXERIS_TOKEN_ISSUER_KEKS_FILE", "k1:" + m.get("TOKEN_KEKS"));
        env.put("EXERIS_MFA_TOTP_KEKS_FILE", "k1:" + m.get("MFA_KEKS"));
        env.put("EXERIS_MFA_TOTP_PEPPER_FILE", m.get("PEPPER"));
        env.put("EXERIS_FEDERATED_LOGIN_STATE_KEYS_FILE", "k1:" + m.get("FEDERATED"));

        Run run = serve(env);

        assertThat(run.status()).isEqualTo(IdentitySkuApplication.EXIT_CONFIG);
        SecretForms.assertNoLeaks(run.output(), "a secret given where a path belongs", m);
    }

    @Test
    @DisplayName("The configuration file setting that holds a value instead of a path is refused without being printed")
    void valueWhereTheConfigurationFileBelongs() throws Exception {
        String pasted = SecretForms.marker();
        Map<String, String> env = unreachable();
        env.put("EXERIS_IDENTITY_CONFIG", pasted);

        Run run = serve(env);

        assertThat(run.status()).isEqualTo(IdentitySkuApplication.EXIT_CONFIG);
        SecretForms.assertNoLeaks(run.output(), "a value where the configuration file's path belongs",
                Map.of("PASTED", pasted));
    }

    @Test
    @DisplayName("A password setting that holds a path and a path setting that holds the password give no password away")
    void passwordFileSettingHoldsThePassword() throws Exception {
        String password = SecretForms.marker();
        Map<String, String> env = unreachable();
        env.remove("EXERIS_DATABASE_PASSWORD");
        env.put("EXERIS_DATABASE_PASSWORD_FILE", password);

        Run run = serve(env);

        assertThat(run.status()).isEqualTo(IdentitySkuApplication.EXIT_CONFIG);
        SecretForms.assertNoLeaks(run.output(), "a password where a path belongs", Map.of("PASSWORD", password));
    }

    // --- the database ---------------------------------------------------------------------------------

    /** The URLs a credential can be carried in; the driver reads only the query form. */
    private static Map<String, String> urlsCarrying(String base, String user, String credential) {
        Map<String, String> urls = new LinkedHashMap<>();
        urls.put("authority", base.replace("://", "://" + user + ":" + credential + "@"));
        urls.put("query", base + "?user=" + user + "&password=" + credential);
        urls.put("semicolon", base + ";password=" + credential);
        return urls;
    }

    @Test
    @DisplayName("(b) A wrong service password exits 69 with SQLSTATE 28P01; a URL with credentials in its authority exits 69 with 08001; neither password is printed")
    void wrongPasswordAndAuthority(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        String wrong = SecretForms.markerWithSpecials();
        Path file = Files.writeString(dir.resolve("p"), SecretForms.marker() + "\r\n");

        for (boolean fromFile : new boolean[]{false, true}) {
            Map<String, String> env = ServeSupport.environment(database, LaunchedProcess.freePort(),
                    InMemoryMembershipDirectory.class.getName());
            String password = wrong;
            if (fromFile) {
                env.remove("EXERIS_DATABASE_PASSWORD");
                env.put("EXERIS_DATABASE_PASSWORD_FILE", file.toString());
                password = Files.readString(file).strip();
            } else {
                env.put("EXERIS_DATABASE_PASSWORD", wrong);
            }

            Run run = serve(env);

            assertThat(run.status()).as(run.output()).isEqualTo(IdentitySkuApplication.EXIT_UNAVAILABLE);
            assertThat(run.output()).contains("SQLSTATE 28P01");
            SecretForms.assertNoLeaks(run.output(), "wrong service password" + (fromFile ? " from a file" : ""),
                    Map.of("PASSWORD", password));
        }

        String inUrl = SecretForms.marker();
        for (Map.Entry<String, String> url : urlsCarrying(database.serviceUrl(), database.serviceUser(), inUrl)
                .entrySet()) {
            Map<String, String> env = ServeSupport.environment(database, LaunchedProcess.freePort(),
                    InMemoryMembershipDirectory.class.getName());
            env.put("EXERIS_DATABASE_URL", url.getValue());
            env.put("EXERIS_DATABASE_PASSWORD", SecretForms.marker());

            Run run = serve(env);

            assertThat(run.status()).as(url.getKey()).isEqualTo(IdentitySkuApplication.EXIT_UNAVAILABLE);
            assertThat(run.output()).contains("SQLSTATE");
            SecretForms.assertNoLeaks(run.output(), "credential in the URL's " + url.getKey(),
                    Map.of("URL", inUrl, "PASSWORD", env.get("EXERIS_DATABASE_PASSWORD")));
        }
    }

    @Test
    @DisplayName("(b) A URL with credentials in its authority and no port, and one the driver cannot parse, are not printed by the driver or the launcher")
    void authorityWithoutPort() throws Exception {
        String inUrl = SecretForms.marker();
        String configured = SecretForms.marker();
        for (String url : new String[]{"jdbc:postgresql://u:" + inUrl + "@127.0.0.1/db",
                "jdbc:postgresql://u:" + inUrl + "@127.0.0.1:" + LaunchedProcess.freePort() + "/db",
                "jdbc:postgresql://u:" + inUrl + "@host:notaport/db",
                "jdbc:postgresql://127.0.0.1:" + LaunchedProcess.freePort() + "/db?password=" + inUrl + "&x=%zz"}) {
            Map<String, String> env = unreachable();
            env.put("EXERIS_DATABASE_URL", url);
            env.put("EXERIS_DATABASE_PASSWORD", configured);

            Run run = serve(env);

            assertThat(run.status()).as(url.replace(inUrl, "<URL>")).isEqualTo(IdentitySkuApplication.EXIT_UNAVAILABLE);
            SecretForms.assertNoLeaks(run.output(), "URL " + url.replace(inUrl, "<URL>"),
                    Map.of("URL", inUrl, "PASSWORD", configured));
        }
    }

    @Test
    @DisplayName("(b) A service role that is a superuser exits 78 and neither the password nor one in the URL is printed")
    void superuserRole() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        Map<String, String> env = ServeSupport.environment(database, LaunchedProcess.freePort(),
                InMemoryMembershipDirectory.class.getName());
        env.put("EXERIS_DATABASE_USER", database.ownerUser());
        env.put("EXERIS_DATABASE_PASSWORD", database.ownerPassword());
        env.put("EXERIS_DATABASE_URL", database.ownerUrl());

        Run run = serve(env);

        assertThat(run.status()).isEqualTo(IdentitySkuApplication.EXIT_CONFIG);
        SecretForms.assertNoLeaks(run.output(), "superuser role", Map.of("PASSWORD", database.ownerPassword()));
    }

    @Test
    @DisplayName("An unreachable host exits 69 with the SQLSTATE and no password")
    void unreachableHost() throws Exception {
        String configured = SecretForms.marker();
        Map<String, String> env = unreachable();
        env.put("EXERIS_DATABASE_PASSWORD", configured);

        Run run = serve(env);

        assertThat(run.status()).isEqualTo(IdentitySkuApplication.EXIT_UNAVAILABLE);
        assertThat(run.output()).contains("SQLSTATE");
        SecretForms.assertNoLeaks(run.output(), "unreachable host", Map.of("PASSWORD", configured));
    }
}
