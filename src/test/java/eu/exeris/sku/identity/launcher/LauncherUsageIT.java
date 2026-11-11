package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.LaunchedProcess;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.DisplayName;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("A command line the launcher does not understand")
class LauncherUsageIT {

    @ParameterizedTest
    @ValueSource(strings = {"serve", "migrate"})
    @DisplayName("A second argument after a command is a usage error with status 64 before any setting is read")
    void secondArgument(String command) throws Exception {
        try (LaunchedProcess process = LaunchedProcess.start(Map.of(), command, "extra")) {
            assertThat(process.awaitExit(60)).as(process.output()).isEqualTo(IdentitySkuApplication.EXIT_USAGE);
            assertThat(process.output()).contains("Usage");
        }
    }
}
