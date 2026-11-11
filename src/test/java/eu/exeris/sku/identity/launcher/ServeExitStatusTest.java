package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.launcher.IdentitySkuApplication.Ending;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Exit status of every way serve can end")
class ServeExitStatusTest {

    /** The status each ending must map to; a new ending has to be decided here. */
    private static final Map<Ending, Integer> EXPECTED = new EnumMap<>(Map.of(
            Ending.STOPPED, 0,
            Ending.KERNEL_NOT_BOOTED, IdentitySkuApplication.EXIT_NOT_COMPLETED,
            Ending.SERVICE_FAILED, IdentitySkuApplication.EXIT_NOT_COMPLETED));

    @Test
    @DisplayName("A service stopped on request exits 0")
    void stopped() {
        assertThat(IdentitySkuApplication.exitStatus(Ending.STOPPED)).isZero();
    }

    @Test
    @DisplayName("A kernel that did not boot exits not completed")
    void kernelNotBooted() {
        assertThat(IdentitySkuApplication.exitStatus(Ending.KERNEL_NOT_BOOTED))
                .isEqualTo(IdentitySkuApplication.EXIT_NOT_COMPLETED);
    }

    @Test
    @DisplayName("A service that failed exits not completed")
    void serviceFailed() {
        assertThat(IdentitySkuApplication.exitStatus(Ending.SERVICE_FAILED))
                .isEqualTo(IdentitySkuApplication.EXIT_NOT_COMPLETED);
    }

    @Test
    @DisplayName("An ending that was never determined exits not completed and never 0")
    void undetermined() {
        assertThat(IdentitySkuApplication.exitStatus(null))
                .isEqualTo(IdentitySkuApplication.EXIT_NOT_COMPLETED)
                .isNotZero();
    }

    @Test
    @DisplayName("Every status the launcher can exit with is different from every other")
    void launcherStatusesAreDistinct() {
        Map<String, Integer> statuses = new java.util.LinkedHashMap<>();
        statuses.put("success", 0);
        statuses.put("EXIT_MIGRATION_FAILED", IdentitySkuApplication.EXIT_MIGRATION_FAILED);
        statuses.put("EXIT_CONFIG", IdentitySkuApplication.EXIT_CONFIG);
        statuses.put("EXIT_UNAVAILABLE", IdentitySkuApplication.EXIT_UNAVAILABLE);
        statuses.put("EXIT_ACCOUNTS_EXIST", IdentitySkuApplication.EXIT_ACCOUNTS_EXIST);
        statuses.put("EXIT_NOT_MIGRATED", IdentitySkuApplication.EXIT_NOT_MIGRATED);
        statuses.put("EXIT_USAGE", IdentitySkuApplication.EXIT_USAGE);
        statuses.put("EXIT_NOT_COMPLETED", IdentitySkuApplication.EXIT_NOT_COMPLETED);

        Set<Integer> seen = new HashSet<>();
        List<String> duplicates = new ArrayList<>();
        statuses.forEach((name, value) -> {
            if (!seen.add(value)) {
                duplicates.add(name + "=" + value);
            }
        });

        assertThat(duplicates).as("statuses sharing a value").isEmpty();
    }

    @Test
    @DisplayName("Every ending has a decided status, and the mapping agrees with it")
    void everyEndingIsDecided() {
        assertThat(EXPECTED.keySet()).containsExactlyInAnyOrder(Ending.values());

        for (Ending ending : Ending.values()) {
            assertThat(IdentitySkuApplication.exitStatus(ending)).as(ending.name())
                    .isEqualTo(EXPECTED.get(ending));
        }
    }
}
