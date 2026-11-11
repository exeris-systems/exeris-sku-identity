package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("migrate against a database that refuses it")
class MigrateRefusalStatusIT {

    @Test
    @DisplayName("Exits with the migration status, which is not the not-completed status of serve")
    void refusedMigrationKeepsItsOwnStatus() throws Exception {
        PostgresSupport.Database database = PostgresSupport.emptyDatabase();
        Map<String, String> env = Map.of(
                "EXERIS_MIGRATE_DATABASE_URL", database.ownerUrl(),
                "EXERIS_MIGRATE_DATABASE_USER", database.serviceUser(),
                "EXERIS_MIGRATE_DATABASE_PASSWORD", database.servicePassword());

        try (LaunchedProcess process = LaunchedProcess.start(env, "migrate")) {
            int status = process.awaitExit(60);

            assertThat(status).as(process.output()).isEqualTo(IdentitySkuApplication.EXIT_MIGRATION_FAILED)
                    .isNotEqualTo(IdentitySkuApplication.EXIT_NOT_COMPLETED);
        }
    }
}
