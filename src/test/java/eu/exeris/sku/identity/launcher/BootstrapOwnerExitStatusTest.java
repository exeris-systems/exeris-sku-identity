package eu.exeris.sku.identity.launcher;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Exit status of every bootstrap-owner outcome")
class BootstrapOwnerExitStatusTest {

    /** The status each permitted outcome type must map to; a new outcome type has to be decided here. */
    private static final Map<Class<?>, Integer> EXPECTED = Map.of(
            OwnerProvisioning.Provisioned.class, 0,
            OwnerProvisioning.AccountsExist.class, IdentitySkuApplication.EXIT_ACCOUNTS_EXIST);

    /** Captures the command's own log records, whatever their level. */
    private static final class Capture extends Handler implements AutoCloseable {

        private final List<LogRecord> records = new ArrayList<>();
        private final Logger logger = Logger.getLogger(BootstrapOwnerCommand.class.getName());
        private final Level savedLevel = logger.getLevel();
        private final boolean savedParents = logger.getUseParentHandlers();

        Capture() {
            setLevel(Level.ALL);
            logger.setLevel(Level.ALL);
            logger.setUseParentHandlers(false);
            logger.addHandler(this);
        }

        @Override
        public synchronized void publish(LogRecord record) {
            records.add(record);
        }

        @Override
        public void flush() {
        }

        synchronized List<LogRecord> records() {
            return List.copyOf(records);
        }

        @Override
        public void close() {
            logger.removeHandler(this);
            logger.setUseParentHandlers(savedParents);
            logger.setLevel(savedLevel);
        }
    }

    @Test
    @DisplayName("An outcome that was never produced is the not-completed status, not a refusal and not success")
    void noOutcomeIsNotCompleted() {
        int status = BootstrapOwnerCommand.exitStatus(null);

        assertThat(status).isEqualTo(IdentitySkuApplication.EXIT_NOT_COMPLETED);
        assertThat(status).isNotEqualTo(IdentitySkuApplication.EXIT_ACCOUNTS_EXIST).isNotZero();
    }

    @Test
    @DisplayName("No outcome does not throw and logs only an error that carries no argument and no exception")
    void noOutcomeLogsNothingSecret() {
        try (Capture capture = new Capture()) {
            int status = BootstrapOwnerCommand.exitStatus(null);

            assertThat(status).isEqualTo(IdentitySkuApplication.EXIT_NOT_COMPLETED);
            assertThat(capture.records()).isNotEmpty().allSatisfy(record -> {
                assertThat(record.getLevel()).isEqualTo(Level.SEVERE);
                assertThat(record.getParameters()).isNullOrEmpty();
                assertThat(record.getThrown()).isNull();
            });
        }
    }

    @Test
    @DisplayName("A provisioned account is success, with a tenant and without one")
    void provisionedIsSuccess() {
        assertThat(BootstrapOwnerCommand.exitStatus(
                new OwnerProvisioning.Provisioned(UUID.randomUUID(), UUID.randomUUID()))).isZero();
        assertThat(BootstrapOwnerCommand.exitStatus(
                new OwnerProvisioning.Provisioned(UUID.randomUUID(), null))).isZero();
    }

    @Test
    @DisplayName("Existing accounts are the accounts-exist status")
    void accountsExistIsRefused() {
        assertThat(BootstrapOwnerCommand.exitStatus(new OwnerProvisioning.AccountsExist()))
                .isEqualTo(IdentitySkuApplication.EXIT_ACCOUNTS_EXIST);
    }

    @Test
    @DisplayName("Every permitted outcome type has an expected status in this test, and no other type is expected")
    void everyPermittedOutcomeIsDecided() {
        Set<Class<?>> permitted = new HashSet<>(List.of(OwnerProvisioning.Outcome.class.getPermittedSubclasses()));

        assertThat(permitted).isNotEmpty();
        assertThat(EXPECTED.keySet())
                .as("an outcome type was added or removed: decide its exit status in EXPECTED")
                .isEqualTo(permitted);
    }

    @Test
    @DisplayName("The mapping agrees with the table for a sample of each permitted outcome type")
    void mappingAgreesWithTable() {
        List<OwnerProvisioning.Outcome> samples = List.of(
                new OwnerProvisioning.Provisioned(UUID.randomUUID(), UUID.randomUUID()),
                new OwnerProvisioning.Provisioned(UUID.randomUUID(), null),
                new OwnerProvisioning.AccountsExist());

        Set<Class<?>> sampled = new HashSet<>();
        for (OwnerProvisioning.Outcome sample : samples) {
            sampled.add(sample.getClass());
            assertThat(BootstrapOwnerCommand.exitStatus(sample))
                    .as(sample.getClass().getSimpleName())
                    .isEqualTo(EXPECTED.get(sample.getClass()));
        }
        assertThat(sampled)
                .as("every permitted outcome type needs a sample")
                .containsExactlyInAnyOrder(OwnerProvisioning.Outcome.class.getPermittedSubclasses());
    }
}
