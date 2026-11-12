package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.launcher.BootstrapOwnerSupport.Run;
import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Neither the owner's password, nor the service password, nor the owner's address reaches the output of
 * {@code bootstrap-owner}, whichever way it ends. Every case runs the launcher in a process of its own.
 */
@DisplayName("bootstrap-owner: no secret reaches the output")
class BootstrapOwnerSecretsIT {

    private static String password() {
        return SecretForms.markerWithSpecials().replace(" x", "z");
    }

    private static Map<String, String> secrets(String owner, String service, String address) {
        Map<String, String> all = new LinkedHashMap<>();
        all.put("OWNER_PASSWORD", owner);
        if (service != null) {
            all.put("SERVICE_PASSWORD", service);
        }
        if (address != null) {
            all.put("ADDRESS", address);
        }
        return all;
    }

    private static String address() {
        return "owner." + SecretForms.lowerCaseMarker() + "@example.test";
    }

    private static Map<String, String> environment(PostgresSupport.Database database, Path file, String address)
            throws Exception {
        Map<String, String> env = BootstrapOwnerSupport.environment(database, file);
        env.put(BootstrapOwnerSupport.EMAIL, address);
        return env;
    }

    private static Map<String, String> licensed(Map<String, String> env) {
        String manifest = System.getenv(LaunchedProcess.DEVELOPER_LICENCE_VARIABLE);
        if (manifest == null || manifest.isBlank()) {
            throw new AssertionError(LaunchedProcess.DEVELOPER_LICENCE_VARIABLE + " is not set: a developer "
                    + "licence is required to boot the kernel");
        }
        env.put(LaunchedProcess.LICENCE_VARIABLE, manifest);
        return env;
    }

    @Test
    @DisplayName("(a) A password outside the policy's window, read from a file that ends in a line break, is refused with status 78 without being printed")
    void policyRefusal(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        String owner = password();
        String address = address();
        Map<String, String> env = environment(database, BootstrapOwnerSupport.passwordFile(dir, owner + "\n"), address);
        env.put("EXERIS_CREDENTIALS_PASSWORD_MIN_LENGTH", "8");
        env.put("EXERIS_CREDENTIALS_PASSWORD_MAX_LENGTH", "12");

        Run run = BootstrapOwnerSupport.run(env);

        assertThat(run.status()).as(run.output()).isEqualTo(BootstrapOwnerSupport.CONFIG);
        assertThat(run.output()).contains(BootstrapOwnerSupport.PASSWORD_FILE);
        SecretForms.assertNoLeaks(run.output(), "policy refusal", secrets(owner, database.servicePassword(), address));
    }

    @Test
    @DisplayName("(a) A refusal after the file was read, a service role that is a superuser, exits 78 and prints neither password nor the address")
    void refusalAfterTheFileWasRead(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        String owner = password();
        String address = address();
        Map<String, String> env = environment(database, BootstrapOwnerSupport.passwordFile(dir, owner), address);
        env.put("EXERIS_DATABASE_URL", database.ownerUrl());
        env.put("EXERIS_DATABASE_USER", database.ownerUser());
        env.put("EXERIS_DATABASE_PASSWORD", database.ownerPassword());

        Run run = BootstrapOwnerSupport.run(env);

        assertThat(run.status()).as(run.output()).isEqualTo(BootstrapOwnerSupport.CONFIG);
        assertThat(run.output()).contains("NOSUPERUSER");
        SecretForms.assertNoLeaks(run.output(), "superuser role", secrets(owner, database.ownerPassword(), address));
    }

    @Test
    @DisplayName("(a) A database that cannot be used after the file was read exits 69 and prints neither password nor the address, for a wrong password and for credentials in the URL")
    void databaseRefusesAfterTheFileWasRead(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        String owner = password();
        String address = address();
        String wrong = SecretForms.marker();
        String inUrl = SecretForms.marker();
        Map<String, String> urls = new LinkedHashMap<>();
        urls.put("wrong password", database.serviceUrl());
        urls.put("authority", database.serviceUrl().replace("://", "://u:" + inUrl + "@"));
        urls.put("authority without a port", "jdbc:postgresql://u:" + inUrl + "@127.0.0.1/db");
        urls.put("query", database.serviceUrl() + "?password=" + inUrl);
        for (Map.Entry<String, String> url : urls.entrySet()) {
            Map<String, String> env = environment(database, BootstrapOwnerSupport.passwordFile(dir, owner), address);
            env.put("EXERIS_DATABASE_URL", url.getValue());
            env.put("EXERIS_DATABASE_PASSWORD", wrong);

            Run run = BootstrapOwnerSupport.run(env);

            assertThat(run.status()).as(url.getKey()).isEqualTo(BootstrapOwnerSupport.UNAVAILABLE);
            Map<String, String> all = secrets(owner, wrong, address);
            all.put("URL", inUrl);
            SecretForms.assertNoLeaks(run.output(), url.getKey(), all);
        }
    }

    @Test
    @DisplayName("(a) An address that is too long is refused with status 78 without being printed")
    void longAddress(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        String owner = password();
        String address = SecretForms.lowerCaseMarker() + "x".repeat(320) + "@example.test";
        Map<String, String> env = environment(database, BootstrapOwnerSupport.passwordFile(dir, owner), address);

        Run run = BootstrapOwnerSupport.run(env);

        assertThat(run.status()).as(run.output()).isEqualTo(BootstrapOwnerSupport.CONFIG);
        SecretForms.assertNoLeaks(run.output(), "long address", secrets(owner, database.servicePassword(), address));
    }

    @Test
    @DisplayName("(c) Without a licence the kernel does not boot: status 70, and neither password nor the address is printed")
    void kernelDoesNotBoot(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        String owner = password();
        String address = address();
        Map<String, String> env = environment(database, BootstrapOwnerSupport.passwordFile(dir, owner), address);

        Run run = BootstrapOwnerSupport.run(env);

        assertThat(run.status()).as(run.output()).isEqualTo(BootstrapOwnerSupport.NOT_COMPLETED);
        assertThat(run.output()).contains("The kernel did not boot");
        SecretForms.assertNoLeaks(run.output(), "kernel did not boot", secrets(owner, database.servicePassword(), address));
    }

    @Test
    @Tag("kernel-boot")
    @DisplayName("(c) A kernel that cannot open its pool exits 70 and prints neither the service password nor the owner password nor the address")
    void kernelCannotOpenItsPool(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        String role = "limited_" + SecretForms.lowerCaseMarker();
        String service = SecretForms.marker();
        try (var owner = database.owner(); var statement = owner.createStatement()) {
            statement.execute("CREATE ROLE " + role + " LOGIN PASSWORD '" + service
                    + "' NOSUPERUSER NOBYPASSRLS CONNECTION LIMIT 1");
        }
        String ownerPassword = password();
        String address = address();
        Map<String, String> env = licensed(environment(database,
                BootstrapOwnerSupport.passwordFile(dir, ownerPassword), address));
        env.put("EXERIS_DATABASE_USER", role);
        env.put("EXERIS_DATABASE_PASSWORD", service);
        env.put("EXERIS_DATABASE_URL", database.serviceUrl() + "?ssl=false");
        env.put("EXERIS_DATABASE_MAX_POOL_SIZE", "10");

        Run run = BootstrapOwnerSupport.run(env);

        assertThat(run.status()).as(run.output()).isEqualTo(BootstrapOwnerSupport.NOT_COMPLETED);
        Map<String, String> all = secrets(ownerPassword, service, address);
        SecretForms.assertNoLeaks(run.output(), "kernel pool", all);
    }

    @Test
    @Tag("kernel-boot")
    @DisplayName("(b) A role that may not use the credential table exits 65 and prints neither password nor the address")
    void roleCheckAfterTheKernelBooted(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        BootstrapOwnerSupport.revoke(database, "SELECT, INSERT");
        String owner = password();
        String address = address();
        Map<String, String> env = licensed(environment(database, BootstrapOwnerSupport.passwordFile(dir, owner), address));

        Run run = BootstrapOwnerSupport.run(env);

        assertThat(run.status()).as(run.output()).isEqualTo(BootstrapOwnerSupport.NOT_MIGRATED);
        SecretForms.assertNoLeaks(run.output(), "role may not use the table", secrets(owner, database.servicePassword(), address));
    }

    @Test
    @Tag("kernel-boot")
    @DisplayName("(b) A credential table under row-level security exits 78 and prints neither password nor the address")
    void credentialTableUnderRowLevelSecurity(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        BootstrapOwnerSupport.enableRowLevelSecurity(database);
        String owner = password();
        String address = address();
        Map<String, String> env = licensed(environment(database, BootstrapOwnerSupport.passwordFile(dir, owner), address));

        Run run = BootstrapOwnerSupport.run(env);

        assertThat(run.status()).as(run.output()).isEqualTo(BootstrapOwnerSupport.CONFIG);
        SecretForms.assertNoLeaks(run.output(), "row-level security", secrets(owner, database.servicePassword(), address));
    }

    @Test
    @Tag("kernel-boot")
    @DisplayName("(a) An address the credential store does not accept exits 78 after the file was read, names the setting and not the address")
    void badAddress(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        String owner = password();
        String address = "not an address " + SecretForms.marker();
        Map<String, String> env = licensed(environment(database, BootstrapOwnerSupport.passwordFile(dir, owner), address));

        Run run = BootstrapOwnerSupport.run(env);

        assertThat(run.status()).as(run.output()).isEqualTo(BootstrapOwnerSupport.CONFIG);
        assertThat(run.output()).contains(BootstrapOwnerSupport.EMAIL + " is not a usable address");
        SecretForms.assertNoLeaks(run.output(), "bad address", secrets(owner, database.servicePassword(), address));
    }

    @Test
    @Tag("kernel-boot")
    @DisplayName("(d) Success creates the account and prints neither password, the address nor a token")
    void success(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        String owner = password();
        String address = address();
        Map<String, String> env = licensed(environment(database, BootstrapOwnerSupport.passwordFile(dir, owner + "\r\n"), address));

        Run run = BootstrapOwnerSupport.run(env);

        assertThat(run.status()).as(run.output()).isZero();
        assertThat(BootstrapOwnerSupport.accounts(database)).isOne();
        assertThat(run.output()).contains("created and verified");
        SecretForms.assertNoLeaks(run.output(), "success", secrets(owner, database.servicePassword(), address));
        assertThat(run.output()).doesNotContain("eyJ");
    }

    @Test
    @Tag("kernel-boot")
    @DisplayName("(d) A second run, refused because an account exists, exits 73 and prints neither password nor the address")
    void accountExists(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        String owner = password();
        String address = address();
        Map<String, String> env = licensed(environment(database, BootstrapOwnerSupport.passwordFile(dir, owner), address));
        assertThat(BootstrapOwnerSupport.run(env).status()).isZero();

        Run second = BootstrapOwnerSupport.run(env);

        assertThat(second.status()).as(second.output()).isEqualTo(BootstrapOwnerSupport.ACCOUNTS_EXIST);
        SecretForms.assertNoLeaks(second.output(), "account exists", secrets(owner, database.servicePassword(), address));
    }
}
