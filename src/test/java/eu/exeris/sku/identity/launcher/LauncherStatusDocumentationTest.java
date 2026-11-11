package eu.exeris.sku.identity.launcher;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The launcher reference lists the statuses of the commands; the constants the launcher exits with must be
 * the ones it lists, and it must list no status the launcher cannot exit with.
 */
@DisplayName("The launcher reference lists the statuses the launcher exits with")
class LauncherStatusDocumentationTest {

    private static final Path REFERENCE = Path.of("docs", "reference", "launcher.md");
    private static final Pattern ROW = Pattern.compile("^\\|\\s*(`[a-z-]+`|either)\\s*\\|\\s*(\\d+)\\b.*\\|\\s*$");

    private static Set<Integer> documented(String command) throws IOException {
        Set<Integer> statuses = new TreeSet<>();
        for (String line : Files.readAllLines(REFERENCE)) {
            Matcher row = ROW.matcher(line);
            if (row.matches() && row.group(1).equals(command)) {
                statuses.add(Integer.parseInt(row.group(2)));
            }
        }
        return statuses;
    }

    private static Set<Integer> bootstrapOwnerStatuses() throws IOException {
        Set<Integer> statuses = new TreeSet<>();
        List<String> lines = Files.readAllLines(REFERENCE);
        boolean inSection = false;
        for (String line : lines) {
            if (line.startsWith("## ")) {
                inSection = line.contains("bootstrap-owner");
            }
            Matcher row = Pattern.compile("^\\|\\s*(\\d+)\\s*\\|.*\\|\\s*$").matcher(line);
            if (inSection && row.matches()) {
                statuses.add(Integer.parseInt(row.group(1)));
            }
        }
        return statuses;
    }

    @Test
    @DisplayName("migrate lists exactly the statuses of its three endings")
    void migrate() throws IOException {
        assertThat(documented("`migrate`")).containsExactlyInAnyOrder(0, IdentitySkuApplication.EXIT_MIGRATION_FAILED,
                IdentitySkuApplication.EXIT_CONFIG);
    }

    @Test
    @DisplayName("serve lists the statuses of its endings: 0, the signal's, unavailable, not completed and config")
    void serve() throws IOException {
        List<Integer> expected = new ArrayList<>(List.of(0, 143, IdentitySkuApplication.EXIT_UNAVAILABLE,
                IdentitySkuApplication.EXIT_NOT_COMPLETED, IdentitySkuApplication.EXIT_CONFIG));

        assertThat(documented("`serve`")).containsExactlyInAnyOrderElementsOf(expected);
    }

    @Test
    @DisplayName("The usage status is listed for either command")
    void usage() throws IOException {
        assertThat(documented("either")).containsExactly(IdentitySkuApplication.EXIT_USAGE);
    }

    @Test
    @DisplayName("bootstrap-owner lists exactly the statuses it can end with")
    void bootstrapOwner() throws IOException {
        assertThat(bootstrapOwnerStatuses()).containsExactlyInAnyOrder(0, IdentitySkuApplication.EXIT_USAGE,
                IdentitySkuApplication.EXIT_NOT_MIGRATED, IdentitySkuApplication.EXIT_UNAVAILABLE,
                IdentitySkuApplication.EXIT_NOT_COMPLETED, IdentitySkuApplication.EXIT_ACCOUNTS_EXIST,
                IdentitySkuApplication.EXIT_CONFIG);
    }
}
