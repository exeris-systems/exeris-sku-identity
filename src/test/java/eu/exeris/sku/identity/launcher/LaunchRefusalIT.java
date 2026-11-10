package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.RecordingInvitationDelivery;
import eu.exeris.sku.identity.support.RecordingNotificationDispatcher;
import eu.exeris.sku.identity.support.TestConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Cases in which the launcher must not get as far as serving. None of them needs a licence: they end
 * either before the kernel starts or at the kernel's own licence gate.
 */
@DisplayName("Launcher refuses to start")
class LaunchRefusalIT {

    @Test
    @DisplayName("With no configuration at all it exits with the configuration status and names the settings")
    void emptyEnvironment() throws Exception {
        try (LaunchedProcess process = LaunchedProcess.start(Map.of())) {
            assertThat(process.awaitExit(60)).as(process.output()).isEqualTo(IdentitySkuApplication.EXIT_CONFIG);
            assertThat(process.output()).contains("EXERIS_TOKEN_ISSUER_ISSUER", "EXERIS_DATABASE_URL");
        }
    }

    @Test
    @DisplayName("A production-class environment with no host parts exits with the configuration status and names them")
    void productionWithoutDirectory() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        Map<String, String> env = LaunchedProcess.serviceEnvironment(
                database, LaunchedProcess.freePort(), TestConfig.env());
        env.put("EXERIS_ENVIRONMENT", "production");

        try (LaunchedProcess process = LaunchedProcess.start(env)) {
            assertThat(process.awaitExit(60)).as(process.output()).isEqualTo(IdentitySkuApplication.EXIT_CONFIG);
            assertThat(process.output()).contains("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY",
                    "EXERIS_IDENTITY_NOTIFICATION_DISPATCHER", "EXERIS_IDENTITY_INVITATION_DELIVERY");
        }
    }

    @Test
    @DisplayName("Production with a directory and a dispatcher but no invitation delivery exits with the configuration status")
    void productionWithoutInvitationDelivery() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        Map<String, String> env = LaunchedProcess.serviceEnvironment(
                database, LaunchedProcess.freePort(), TestConfig.env());
        env.put("EXERIS_ENVIRONMENT", "production");
        env.put("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY", InMemoryMembershipDirectory.class.getName());
        env.put("EXERIS_IDENTITY_NOTIFICATION_DISPATCHER", RecordingNotificationDispatcher.class.getName());

        try (LaunchedProcess process = LaunchedProcess.start(env)) {
            assertThat(process.awaitExit(60)).as(process.output()).isEqualTo(IdentitySkuApplication.EXIT_CONFIG);
            assertThat(process.output()).contains("EXERIS_IDENTITY_INVITATION_DELIVERY");
        }
    }

    @Test
    @DisplayName("An environment that is not declared exits with the configuration status and names the variable")
    void environmentNotDeclared() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        Map<String, String> env = LaunchedProcess.serviceEnvironment(
                database, LaunchedProcess.freePort(), TestConfig.env());

        try (LaunchedProcess process = LaunchedProcess.start(env)) {
            assertThat(process.awaitExit(60)).as(process.output()).isEqualTo(IdentitySkuApplication.EXIT_CONFIG);
            assertThat(process.output()).contains("EXERIS_ENVIRONMENT is not set");
        }
    }

    @Test
    @DisplayName("A kernel environment property that disagrees with EXERIS_ENVIRONMENT exits with the configuration status")
    void environmentDisagreesWithTheKernelProperty() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        Map<String, String> env = LaunchedProcess.serviceEnvironment(
                database, LaunchedProcess.freePort(), TestConfig.env());
        env.put("EXERIS_ENVIRONMENT", "staging");

        try (LaunchedProcess process = LaunchedProcess.start(env, List.of("-Dexeris.environment=production"))) {
            assertThat(process.awaitExit(60)).as(process.output()).isEqualTo(IdentitySkuApplication.EXIT_CONFIG);
            assertThat(process.output()).contains("exeris.environment");
        }
    }

    @Test
    @DisplayName("A service role that is a superuser exits with the configuration status")
    void superuserServiceRole() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        Map<String, String> env = LaunchedProcess.serviceEnvironment(
                database, LaunchedProcess.freePort(), TestConfig.env());
        env.put("EXERIS_ENVIRONMENT", "development");
        env.put("EXERIS_DATABASE_URL", database.ownerUrl());
        env.put("EXERIS_DATABASE_USER", database.ownerUser());
        env.put("EXERIS_DATABASE_PASSWORD", database.ownerPassword());

        try (LaunchedProcess process = LaunchedProcess.start(env)) {
            assertThat(process.awaitExit(60)).as(process.output()).isEqualTo(IdentitySkuApplication.EXIT_CONFIG);
            assertThat(process.output()).contains("NOSUPERUSER and NOBYPASSRLS");
        }
    }

    @Test
    @DisplayName("An unreachable database exits with the unavailable status")
    void unreachableDatabase() throws Exception {
        Map<String, String> env = new HashMap<>(TestConfig.env());
        env.put("EXERIS_DATABASE_URL", "jdbc:postgresql://127.0.0.1:" + LaunchedProcess.freePort() + "/identity");
        env.put("EXERIS_DATABASE_USER", "identity_service");
        env.put("EXERIS_DATABASE_PASSWORD", TestConfig.randomBase64(12));
        env.put("EXERIS_HTTP_PORT", String.valueOf(LaunchedProcess.freePort()));
        env.put("EXERIS_ENVIRONMENT", "development");

        try (LaunchedProcess process = LaunchedProcess.start(env)) {
            assertThat(process.awaitExit(60)).as(process.output()).isEqualTo(IdentitySkuApplication.EXIT_UNAVAILABLE);
        }
    }

    @Test
    @DisplayName("An unknown command line exits with the usage status")
    void unknownCommand() throws Exception {
        try (LaunchedProcess process = LaunchedProcess.start(Map.of(), "frobnicate")) {
            assertThat(process.awaitExit(60)).as(process.output()).isEqualTo(IdentitySkuApplication.EXIT_USAGE);
        }
    }

    @Test
    @DisplayName("A production environment with a complete configuration and no licence manifest does not start")
    void productionWithoutManifest() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        int port = LaunchedProcess.freePort();
        Map<String, String> env = LaunchedProcess.serviceEnvironment(database, port, TestConfig.env());
        env.put("EXERIS_ENVIRONMENT", "production");
        env.put("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY", InMemoryMembershipDirectory.class.getName());
        env.put("EXERIS_IDENTITY_NOTIFICATION_DISPATCHER", RecordingNotificationDispatcher.class.getName());
        env.put("EXERIS_IDENTITY_INVITATION_DELIVERY", RecordingInvitationDelivery.class.getName());

        try (LaunchedProcess process = LaunchedProcess.start(env)) {
            int status = process.awaitExit(60);

            assertThat(status).as(process.output()).isNotZero().isNotEqualTo(IdentitySkuApplication.EXIT_CONFIG);
            assertThat(process.output()).contains("No license manifest found");
        }
    }
}
