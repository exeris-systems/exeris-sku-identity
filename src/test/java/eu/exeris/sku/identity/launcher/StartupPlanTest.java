package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.config.IdentityConfigException;
import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.TestConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Startup plan: what must be complete before the kernel boots")
class StartupPlanTest {

    private static final String DIRECTORY = InMemoryMembershipDirectory.class.getName();

    private static Map<String, String> complete() {
        Map<String, String> env = new HashMap<>(TestConfig.env());
        env.put("EXERIS_DATABASE_URL", "jdbc:postgresql://db.example.test:5432/identity");
        env.put("EXERIS_DATABASE_USER", "identity_service");
        env.put("EXERIS_DATABASE_PASSWORD", TestConfig.randomBase64(12));
        return env;
    }

    private static IdentityConfigException refused(Map<String, String> env) {
        Throwable thrown = org.assertj.core.api.Assertions.catchThrowable(() -> StartupPlan.prepare(env));
        assertThat(thrown).isInstanceOf(IdentityConfigException.class);
        return (IdentityConfigException) thrown;
    }

    @Test
    @DisplayName("A complete development environment is accepted and maps to the kernel's settings")
    void completeDevelopment() {
        Map<String, String> env = complete();
        StartupPlan plan = StartupPlan.prepare(env);

        assertThat(plan.productionClass()).isFalse();
        assertThat(plan.membershipDirectory()).isInstanceOf(UnconfiguredMembershipDirectory.class);
        Map<String, String> kernel = plan.kernelProperties();
        assertThat(kernel).containsEntry("exeris.http.mode", "SERVER")
                .containsEntry("exeris.http.bindHost", "127.0.0.1")
                .containsEntry("exeris.http.port", "8080")
                .containsEntry("exeris.persistence.jdbcUrl", env.get("EXERIS_DATABASE_URL"))
                .containsEntry("exeris.persistence.username", "identity_service")
                .containsEntry("exeris.persistence.password", env.get("EXERIS_DATABASE_PASSWORD"))
                .containsEntry("exeris.persistence.maxPoolSize", "10");
    }

    @Test
    @DisplayName("An empty environment is refused with every missing setting named once")
    void emptyEnvironment() {
        IdentityConfigException refusal = refused(Map.of());

        String all = String.join("\n", refusal.problems());
        assertThat(all).contains("EXERIS_TOKEN_ISSUER_ISSUER", "EXERIS_TOKEN_ISSUER_AUDIENCE",
                "EXERIS_DATABASE_URL", "EXERIS_DATABASE_USER", "EXERIS_DATABASE_PASSWORD");
        assertThat(refusal.problems().size()).isGreaterThanOrEqualTo(6);
    }

    @Test
    @DisplayName("Each database setting is required on its own")
    void databaseSettingsAreEachRequired() {
        for (String key : new String[] {"EXERIS_DATABASE_URL", "EXERIS_DATABASE_USER", "EXERIS_DATABASE_PASSWORD"}) {
            Map<String, String> env = complete();
            env.remove(key);

            assertThat(refused(env).problems()).singleElement().asString().contains(key);
        }
    }

    @Test
    @DisplayName("A URL that is not PostgreSQL, and a pool size out of range, are refused")
    void databaseValuesAreChecked() {
        Map<String, String> env = complete();
        env.put("EXERIS_DATABASE_URL", "jdbc:h2:mem:identity");
        env.put("EXERIS_DATABASE_MAX_POOL_SIZE", "0");

        assertThat(String.join("\n", refused(env).problems()))
                .contains("EXERIS_DATABASE_URL must be a jdbc:postgresql: URL")
                .contains("EXERIS_DATABASE_MAX_POOL_SIZE must be between 1 and 1000");
    }

    @Test
    @DisplayName("The password comes from a file or inline, never both, and the text form withholds it")
    void passwordSources(@TempDir Path dir) throws IOException {
        Map<String, String> env = complete();
        String inline = env.remove("EXERIS_DATABASE_PASSWORD");
        Path file = dir.resolve("db-password");
        Files.writeString(file, inline + "\n");
        env.put("EXERIS_DATABASE_PASSWORD_FILE", file.toString());

        StartupPlan plan = StartupPlan.prepare(env);
        assertThat(plan.database().password()).isEqualTo(inline);
        assertThat(plan.database().toString()).doesNotContain(inline);
        assertThat(plan.toString()).doesNotContain(inline);

        env.put("EXERIS_DATABASE_PASSWORD", inline);
        assertThat(refused(env).problems()).singleElement().asString()
                .contains("Only one of EXERIS_DATABASE_PASSWORD and EXERIS_DATABASE_PASSWORD_FILE");

        env.remove("EXERIS_DATABASE_PASSWORD");
        env.put("EXERIS_DATABASE_PASSWORD_FILE", dir.resolve("absent").toString());
        assertThat(refused(env).problems()).singleElement().asString()
                .contains("EXERIS_DATABASE_PASSWORD_FILE does not name a readable file");
    }

    @Test
    @DisplayName("A production-class environment without a membership directory is refused")
    void productionNeedsDirectory() {
        for (String environment : new String[] {"production", "production-load-sim", "dr-hot"}) {
            Map<String, String> env = complete();
            env.put("EXERIS_ENVIRONMENT", environment);

            assertThat(refused(env).problems()).singleElement().asString()
                    .contains("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY").contains("production-class");
        }
    }

    @Test
    @DisplayName("An environment the kernel does not know is treated as production-class")
    void unknownEnvironmentFailsClosed() {
        Map<String, String> env = complete();
        env.put("EXERIS_ENVIRONMENT", "prod-ish");

        assertThat(refused(env).problems()).singleElement().asString()
                .contains("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY");
    }

    @Test
    @DisplayName("A production-class environment with a directory is accepted")
    void productionWithDirectory() {
        Map<String, String> env = complete();
        env.put("EXERIS_ENVIRONMENT", "production");
        env.put("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY", DIRECTORY);

        StartupPlan plan = StartupPlan.prepare(env);

        assertThat(plan.productionClass()).isTrue();
        assertThat(plan.membershipDirectory()).isInstanceOf(InMemoryMembershipDirectory.class);
    }

    @Test
    @DisplayName("Staging and dr-cold do not serve live traffic and need no directory")
    void nonProductionClassesNeedNoDirectory() {
        for (String environment : new String[] {"development", "staging", "dr-cold"}) {
            Map<String, String> env = complete();
            env.put("EXERIS_ENVIRONMENT", environment);

            assertThat(StartupPlan.prepare(env).productionClass()).isFalse();
        }
    }

    @Test
    @DisplayName("A host part that cannot be loaded, or is the wrong type, is named and refused")
    void hostPartsAreChecked() {
        Map<String, String> env = complete();
        env.put("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY", "example.absent.Directory");
        env.put("EXERIS_IDENTITY_NOTIFICATION_DISPATCHER", String.class.getName());

        assertThat(String.join("\n", refused(env).problems()))
                .contains("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY names a class that cannot be loaded")
                .contains("EXERIS_IDENTITY_NOTIFICATION_DISPATCHER names a class that is not a NotificationDispatcher");
    }

    @Test
    @DisplayName("The migration command needs its own database settings and refuses a bad role name")
    void migrateSettings() {
        assertThatThrownBy(() -> Migrate.run(Map.of())).isInstanceOf(IdentityConfigException.class)
                .satisfies(e -> assertThat(((IdentityConfigException) e).problems()).hasSize(3));

        Map<String, String> env = new HashMap<>();
        env.put("EXERIS_MIGRATE_DATABASE_URL", "jdbc:postgresql://db.example.test/identity");
        env.put("EXERIS_MIGRATE_DATABASE_USER", "owner");
        env.put("EXERIS_MIGRATE_DATABASE_PASSWORD", TestConfig.randomBase64(12));
        env.put("EXERIS_MIGRATE_SERVICE_ROLE", "bad\"; DROP");
        assertThatThrownBy(() -> Migrate.run(env)).isInstanceOf(IdentityConfigException.class)
                .hasMessageContaining("EXERIS_MIGRATE_SERVICE_ROLE");
    }
}
