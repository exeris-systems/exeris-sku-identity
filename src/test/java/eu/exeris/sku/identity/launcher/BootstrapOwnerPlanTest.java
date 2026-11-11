package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.TestConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Startup plan as the bootstrap-owner command uses it")
class BootstrapOwnerPlanTest {

    private static Map<String, String> complete() {
        Map<String, String> env = new HashMap<>(TestConfig.env());
        env.put("EXERIS_DATABASE_URL", "jdbc:postgresql://db.example.test:5432/identity");
        env.put("EXERIS_DATABASE_USER", "identity_service");
        env.put("EXERIS_DATABASE_PASSWORD", TestConfig.randomBase64(12));
        env.put("EXERIS_ENVIRONMENT", "development");
        return env;
    }

    @Test
    @DisplayName("The persistence settings are the database's, bind no listener, and are all part of the serve settings")
    void persistencePropertiesAreASubsetOfKernelProperties() {
        Map<String, String> env = complete();
        StartupPlan plan = StartupPlan.prepare(env);

        Map<String, String> persistence = plan.persistenceProperties();
        Map<String, String> kernel = plan.kernelProperties();

        assertThat(persistence).containsEntry("exeris.environment", "development")
                .containsEntry("exeris.persistence.rlsEnabled", "true")
                .containsEntry("exeris.persistence.jdbcUrl", env.get("EXERIS_DATABASE_URL"))
                .containsEntry("exeris.persistence.username", "identity_service")
                .containsEntry("exeris.persistence.password", env.get("EXERIS_DATABASE_PASSWORD"));
        assertThat(persistence.keySet()).noneMatch(key -> key.startsWith("exeris.http."));
        assertThat(kernel).containsAllEntriesOf(persistence);
        assertThat(kernel).containsEntry("exeris.http.mode", "SERVER").containsEntry("exeris.http.port", "8080")
                .containsEntry("exeris.persistence.maxPoolSize", "10");
    }

    @Test
    @DisplayName("A directory is configured exactly when the host named one")
    void membershipDirectoryDetection() {
        assertThat(StartupPlan.prepare(complete()).hasMembershipDirectory()).isFalse();

        Map<String, String> env = complete();
        env.put("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY", InMemoryMembershipDirectory.class.getName());
        assertThat(StartupPlan.prepare(env).hasMembershipDirectory()).isTrue();
    }
}
