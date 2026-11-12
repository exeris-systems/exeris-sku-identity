package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.TestConfig;
import eu.exeris.sku.identity.support.process.ErrorOnGrantMembershipDirectory;
import eu.exeris.sku.identity.support.process.FileMembershipDirectory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static eu.exeris.sku.identity.launcher.BootstrapOwnerSupport.*;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * How {@code bootstrap-owner} ends when a host part throws an {@link Error} at the point the command calls
 * it: the membership directory's grant, inside the transaction that has written the account.
 */
@Tag("kernel-boot")
@DisplayName("bootstrap-owner ends on an Error")
class BootstrapOwnerErrorEndingsIT {

    private static Map<String, String> environment(PostgresSupport.Database database, Path dir, Path hostDirectory,
                                                   String kind, String marker, String password) throws Exception {
        String manifest = System.getenv(LaunchedProcess.DEVELOPER_LICENCE_VARIABLE);
        if (manifest == null || manifest.isBlank()) {
            throw new AssertionError(LaunchedProcess.DEVELOPER_LICENCE_VARIABLE + " is not set: a developer licence "
                    + "entitling exeris-sku-identity and its nine commercial capabilities is required to boot "
                    + "the kernel");
        }
        Map<String, String> env = BootstrapOwnerSupport.environment(database, passwordFile(dir, password));
        env.put("EXERIS_TOKEN_ISSUER_MANUAL_ROTATION", "false");
        env.put(LaunchedProcess.LICENCE_VARIABLE, manifest);
        withDirectory(env, hostDirectory, UUID.randomUUID());
        env.put("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY", ErrorOnGrantMembershipDirectory.class.getName());
        env.put(ErrorOnGrantMembershipDirectory.KIND_VARIABLE, kind);
        env.put(ErrorOnGrantMembershipDirectory.MARKER_VARIABLE, marker);
        return env;
    }

    @Test
    @DisplayName("A class that cannot be loaded exits not completed with one error line naming the class, no message, no trace and no account; a later run succeeds")
    void classThatCannotBeLoaded(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        Path hostDirectory = Files.createDirectory(dir.resolve("host"));
        String marker = "marker-" + UUID.randomUUID();
        String password = new String(TestConfig.randomPassword());
        Map<String, String> env = environment(database, dir, hostDirectory, ErrorOnGrantMembershipDirectory.NO_CLASS_DEF,
                marker, password);

        Run run = run(env);

        assertThat(run.status()).as(run.output()).isEqualTo(NOT_COMPLETED);
        List<String> naming = run.output().lines().filter(line -> line.contains("java.lang.NoClassDefFoundError")).toList();
        assertThat(naming).as("lines naming the error" + System.lineSeparator() + run.output()).hasSize(1);
        assertThat(naming.getFirst()).containsPattern("SEVERE|ERROR");
        assertThat(run.output()).doesNotContain(marker).doesNotContain("grant error")
                .doesNotContain("Exception in thread").doesNotContain("Caused by")
                .doesNotContainPattern("(?m)^\\s+at [a-z]").doesNotContain(password);
        assertThat(accounts(database)).as("accounts left behind").isZero();
        assertThat(grants(hostDirectory)).isEmpty();

        env.put("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY", FileMembershipDirectory.class.getName());
        Run again = run(env);

        assertThat(again.status()).as(again.output()).isEqualTo(OK);
        assertThat(accounts(database)).isEqualTo(1);
    }

    @Test
    @DisplayName("An OutOfMemoryError exits not completed at once, names the class once, prints no message or trace and leaves no account")
    void outOfMemory(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        Path hostDirectory = Files.createDirectory(dir.resolve("host"));
        String marker = "marker-" + UUID.randomUUID();
        String password = new String(TestConfig.randomPassword());
        Map<String, String> env = environment(database, dir, hostDirectory, ErrorOnGrantMembershipDirectory.OUT_OF_MEMORY,
                marker, password);

        Run run = run(env);

        assertThat(run.status()).as(run.output()).isEqualTo(NOT_COMPLETED);
        List<String> naming = run.output().lines().filter(line -> line.contains("java.lang.OutOfMemoryError")).toList();
        assertThat(naming).as("lines naming the error" + System.lineSeparator() + run.output()).hasSize(1);
        assertThat(run.output()).doesNotContain(marker).doesNotContain("grant error")
                .doesNotContain("Exception in thread").doesNotContain("Caused by")
                .doesNotContainPattern("(?m)^\\s+at [a-z]").doesNotContain(password);
        assertThat(accounts(database)).as("accounts left behind").isZero();
        assertThat(grants(hostDirectory)).isEmpty();
    }
}
