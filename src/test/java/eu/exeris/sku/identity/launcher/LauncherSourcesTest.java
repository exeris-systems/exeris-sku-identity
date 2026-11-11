package eu.exeris.sku.identity.launcher;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The launcher does not reach into the credential capability's schema and does not serialise writers with a
 * lock of its own: whether an account exists, and the exclusion between concurrent first-account runs, belong
 * to the credential store's API.
 */
@DisplayName("The launcher's sources and the credential store's schema")
class LauncherSourcesTest {

    private static final Path LAUNCHER = Path.of("src", "main", "java", "eu", "exeris", "sku", "identity", "launcher");

    private static final Pattern CREDENTIAL_TABLE = Pattern.compile("credential_records", Pattern.CASE_INSENSITIVE);
    private static final Pattern ADVISORY_LOCK = Pattern.compile("advisory", Pattern.CASE_INSENSITIVE);

    /** Every line of every Java source under the directory that names the table or takes an advisory lock. */
    private static List<String> offences(Path root) throws IOException {
        List<String> found = new ArrayList<>();
        try (Stream<Path> files = Files.walk(root)) {
            for (Path file : files.filter(f -> f.toString().endsWith(".java")).sorted().toList()) {
                List<String> lines = Files.readAllLines(file);
                for (int i = 0; i < lines.size(); i++) {
                    String line = lines.get(i);
                    if (CREDENTIAL_TABLE.matcher(line).find() || ADVISORY_LOCK.matcher(line).find()) {
                        found.add(root.relativize(file) + ":" + (i + 1) + ": " + line.strip());
                    }
                }
            }
        }
        return found;
    }

    private static long sources(Path root) throws IOException {
        try (Stream<Path> files = Files.walk(root)) {
            return files.filter(f -> f.toString().endsWith(".java")).count();
        }
    }

    @Test
    @DisplayName("No launcher source names the credential table or takes an advisory lock")
    void launcherIsClean() throws IOException {
        assertThat(LAUNCHER).isDirectory();
        assertThat(sources(LAUNCHER)).as("launcher sources scanned").isGreaterThanOrEqualTo(10);

        assertThat(offences(LAUNCHER)).isEmpty();
    }

    @Test
    @DisplayName("The scanner reports a source that names the table, one that takes an advisory lock, and a lower-case spelling")
    void scannerCanFail(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("Reads.java"), "class Reads { String q = \"SELECT 1 FROM credential_records\"; }\n");
        Files.writeString(dir.resolve("Locks.java"),
                "class Locks { String q = \"SELECT pg_advisory_xact_lock(1)\"; }\n");
        Files.writeString(dir.resolve("Shouts.java"), "class Shouts { String q = \"FROM CREDENTIAL_RECORDS\"; }\n");
        Files.writeString(dir.resolve("Clean.java"), "class Clean { }\n");

        List<String> found = offences(dir);

        assertThat(found).hasSize(3);
        assertThat(found).anyMatch(line -> line.startsWith("Reads.java:1"));
        assertThat(found).anyMatch(line -> line.startsWith("Locks.java:1"));
        assertThat(found).anyMatch(line -> line.toLowerCase(Locale.ROOT).startsWith("shouts.java:1"));
        assertThat(found).noneMatch(line -> line.startsWith("Clean.java"));
    }
}
