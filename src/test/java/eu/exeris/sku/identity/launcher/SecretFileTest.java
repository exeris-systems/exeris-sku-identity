package eu.exeris.sku.identity.launcher;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.assertj.core.api.Assumptions.assumeThat;

/**
 * A password file has one reader: the configuration obtains the password from it, and the redaction learns the
 * same password from it. Same bound, same strict decoding, same removal of trailing line breaks.
 */
@DisplayName("SecretFile: one reader for the configuration and the redaction")
class SecretFileTest {

    private static final String KEY = "EXERIS_DATABASE_PASSWORD";

    private static Path file(Path dir, byte[] content) throws IOException {
        return Files.write(Files.createTempFile(dir, "secret-", ".txt"), content);
    }

    private static Path file(Path dir, String content) throws IOException {
        return file(dir, content.getBytes(StandardCharsets.UTF_8));
    }

    // --- the reader ------------------------------------------------------------------------------------

    @Test
    @DisplayName("A file of exactly the bound is read; one byte more is refused as too large")
    void bound(@TempDir Path dir) throws IOException {
        byte[] atBound = new byte[(int) SecretFile.MAXIMUM_BYTES];
        Arrays.fill(atBound, (byte) 'a');
        byte[] over = Arrays.copyOf(atBound, atBound.length + 1);
        Arrays.fill(over, (byte) 'a');

        SecretFile.Read accepted = SecretFile.read(file(dir, atBound));
        SecretFile.Read refused = SecretFile.read(file(dir, over));

        assertThat(SecretFile.MAXIMUM_BYTES).isEqualTo(1024L * 1024L);
        assertThat(accepted.refusal()).isNull();
        assertThat(accepted.content()).hasSize(atBound.length);
        assertThat(refused.refusal()).isEqualTo(SecretFile.Refusal.TOO_LARGE);
        assertThat(refused.content()).isNull();
    }

    @Test
    @DisplayName("The bound is in bytes: a file of multi-byte characters within the bound is read")
    void boundIsInBytes(@TempDir Path dir) throws IOException {
        String twoBytes = "\u00e9".repeat((int) SecretFile.MAXIMUM_BYTES / 2);

        SecretFile.Read read = SecretFile.read(file(dir, twoBytes));

        assertThat(read.refusal()).isNull();
        assertThat(read.content()).isEqualTo(twoBytes);
    }

    @Test
    @DisplayName("An empty file, one of line breaks only, a directory, a missing file, an unreadable file and invalid UTF-8 are refused")
    void refusals(@TempDir Path dir) throws IOException {
        assertThat(SecretFile.read(file(dir, "")).refusal()).isEqualTo(SecretFile.Refusal.EMPTY);
        assertThat(SecretFile.read(file(dir, "\n")).refusal()).isEqualTo(SecretFile.Refusal.EMPTY);
        assertThat(SecretFile.read(file(dir, "\r\n\r\n\n")).refusal()).isEqualTo(SecretFile.Refusal.EMPTY);
        assertThat(SecretFile.read(dir).refusal()).isEqualTo(SecretFile.Refusal.NOT_READABLE);
        assertThat(SecretFile.read(dir.resolve("missing")).refusal()).isEqualTo(SecretFile.Refusal.NOT_READABLE);
        for (byte[] invalid : List.of(new byte[]{'a', (byte) 0xC3}, new byte[]{(byte) 0xFF, 'a'},
                new byte[]{'a', (byte) 0xC0, (byte) 0x80}, new byte[]{(byte) 0xED, (byte) 0xA0, (byte) 0x80})) {
            SecretFile.Read read = SecretFile.read(file(dir, invalid));
            assertThat(read.refusal()).as(Arrays.toString(invalid)).isEqualTo(SecretFile.Refusal.UNREADABLE);
            assertThat(read.content()).isNull();
        }
    }

    @Test
    @DisplayName("A file the process cannot read is refused")
    void unreadable(@TempDir Path dir) throws IOException {
        Path locked = file(dir, "secret");
        assumeThat(Files.getFileStore(locked).supportsFileAttributeView("posix")).isTrue();
        Files.setPosixFilePermissions(locked, PosixFilePermissions.fromString("---------"));
        assumeThat(Files.isReadable(locked)).as("the permissions are enforced for this user").isFalse();

        SecretFile.Read read = SecretFile.read(locked);

        assertThat(read.refusal()).isEqualTo(SecretFile.Refusal.NOT_READABLE);
        assertThat(read.content()).isNull();
    }

    @Test
    @DisplayName("A FIFO is refused at once instead of being read, so a writer that never comes cannot hold the launcher")
    void fifo(@TempDir Path dir) throws Exception {
        Path pipe = dir.resolve("pipe");
        Process made = new ProcessBuilder("mkfifo", pipe.toString()).redirectErrorStream(true).start();
        assumeThat(made.waitFor(10, TimeUnit.SECONDS) && made.exitValue() == 0).as("mkfifo is available").isTrue();

        SecretFile.Read read = assertTimeoutPreemptively(Duration.ofSeconds(10), () -> SecretFile.read(pipe));

        assertThat(read.refusal()).isEqualTo(SecretFile.Refusal.NOT_READABLE);
        assertThat(read.content()).isNull();
    }

    @Test
    @DisplayName("A link to a file is followed, as mounted secrets are links")
    void linkIsFollowed(@TempDir Path dir) throws IOException {
        Path target = file(dir, "linked\n");
        Path link = Files.createSymbolicLink(dir.resolve("link"), target);

        assertThat(SecretFile.read(link).content()).isEqualTo("linked");
    }

    @Test
    @DisplayName("Trailing line breaks are removed and nothing else is: not spaces, tabs, a byte-order mark, inner or leading breaks")
    void onlyTrailingLineBreaksAreRemoved(@TempDir Path dir) throws IOException {
        Map<String, String> expected = new java.util.LinkedHashMap<>();
        expected.put("p", "p");
        expected.put("p\n", "p");
        expected.put("p\r\n", "p");
        expected.put("p\n\n", "p");
        expected.put("p\r\n\r\n", "p");
        expected.put("p\r", "p");
        expected.put("p \n", "p ");
        expected.put("p\t\n", "p\t");
        expected.put(" p\n", " p");
        expected.put("\np\n", "\np");
        expected.put("\r\np", "\r\np");
        expected.put("a\nb\n", "a\nb");
        expected.put("a\r\nb\r\n", "a\r\nb");
        expected.put("a\rb", "a\rb");
        expected.put("p\u00a0\n", "p\u00a0");
        expected.put("\ufeffp\n", "\ufeffp");
        expected.put("  \n", "  ");
        expected.put("\u00e9\u4e2d\ud83d\ude00\n", "\u00e9\u4e2d\ud83d\ude00");

        expected.forEach((content, secret) -> {
            try {
                SecretFile.Read read = SecretFile.read(file(dir, content));
                assertThat(read.refusal()).as(content.replace("\n", "\\n").replace("\r", "\\r")).isNull();
                assertThat(read.content()).isEqualTo(secret);
            } catch (IOException e) {
                throw new AssertionError(e);
            }
        });
    }

    @Test
    @DisplayName("The reader never throws, whatever it is given")
    void neverThrows(@TempDir Path dir) {
        assertThatCode(() -> SecretFile.read(dir.resolve("a\u0000b".replace('\u0000', 'x')))).doesNotThrowAnyException();
        assertThatCode(() -> SecretFile.read(Path.of("/proc/self/mem"))).doesNotThrowAnyException();
        assertThatCode(() -> SecretFile.read(Path.of("/dev/zero"))).doesNotThrowAnyException();
    }

    // --- the configuration names the setting -----------------------------------------------------------

    private static List<String> problemsOf(Map<String, String> env) {
        LauncherEnvironment in = new LauncherEnvironment(env);
        in.secret(KEY);
        return in.problems();
    }

    @Test
    @DisplayName("A refused file is reported by the setting that names it, never by its path or content")
    void configurationNamesTheSetting(@TempDir Path dir) throws IOException {
        String marker = SecretForms.marker();
        Path named = Files.createDirectory(dir.resolve("dir-" + marker));
        byte[] over = new byte[(int) SecretFile.MAXIMUM_BYTES + 1];
        Arrays.fill(over, (byte) 'a');
        Map<String, Path> cases = new java.util.LinkedHashMap<>();
        cases.put("too large", file(dir, over));
        cases.put("empty", file(dir, "\n"));
        cases.put("not utf-8", file(dir, new byte[]{(byte) 0xFF, 'a'}));
        cases.put("directory", named);
        cases.put("missing", dir.resolve("missing-" + marker));

        cases.forEach((what, path) -> {
            List<String> problems = problemsOf(Map.of(KEY + "_FILE", path.toString()));

            assertThat(problems).as(what).hasSize(1);
            assertThat(problems.get(0)).as(what).startsWith(KEY + "_FILE ").doesNotContain(marker)
                    .doesNotContain(path.getFileName().toString()).doesNotContain(dir.toString());
        });
        assertThat(problemsOf(Map.of(KEY + "_FILE", file(dir, over).toString())).get(0))
                .contains(String.valueOf(SecretFile.MAXIMUM_BYTES));
    }

    // --- the configuration and the redaction agree -----------------------------------------------------

    private static final String[] PIECES = {"a", "Z", "7", " ", "\t", "\n", "\r", "\r\n", "\u00e9", "\u4e2d",
        "\ud83d\ude00", "=", "&", "%", "+", "\u00a0", "\ufeff", "-", "'"};

    private static String sample(Random random) {
        StringBuilder text = new StringBuilder();
        int length = random.nextInt(12);
        for (int i = 0; i < length; i++) {
            text.append(PIECES[random.nextInt(PIECES.length)]);
        }
        return text.toString();
    }

    @Test
    @DisplayName("For a seeded sample of contents the configuration obtains the password the redaction learns, and where one refuses the other has nothing")
    void configurationAndRedactionAgree(@TempDir Path dir) throws IOException {
        Random random = new Random(20_260_307L);
        int accepted = 0;
        int refused = 0;
        for (int i = 0; i < 400; i++) {
            String content = sample(random);
            byte[] bytes = random.nextInt(10) == 0 ? new byte[]{'a', (byte) (0x80 + random.nextInt(0x40))}
                    : content.getBytes(StandardCharsets.UTF_8);
            Path path = file(dir, bytes);
            Map<String, String> env = new HashMap<>();
            env.put(KEY + "_FILE", random.nextBoolean() ? path.toString() : "  " + path + "  ");

            LauncherEnvironment in = new LauncherEnvironment(env);
            String configured = in.secret(KEY);
            String[] learned = LauncherLog.secrets(env, "EXERIS_DATABASE");

            if (configured == null) {
                refused++;
                assertThat(in.problems()).as("refusal of %s", Arrays.toString(bytes)).hasSize(1);
                assertThat(learned).as("redaction of a refused file %s", Arrays.toString(bytes)).isEmpty();
            } else {
                accepted++;
                assertThat(in.problems()).isEmpty();
                assertThat(learned).as("redaction of %s", Arrays.toString(bytes)).containsExactly(configured);
            }
        }

        assertThat(accepted).isGreaterThan(100);
        assertThat(refused).isGreaterThan(20);
    }

    @Test
    @DisplayName("When both the password and its file are set the configuration refuses, and the redaction knows both so that the refusal cannot print either")
    void bothSet(@TempDir Path dir) throws IOException {
        String inline = SecretForms.marker();
        String inFile = SecretForms.marker();
        Map<String, String> env = Map.of(KEY, inline, KEY + "_FILE", file(dir, inFile + "\n").toString());

        LauncherEnvironment in = new LauncherEnvironment(env);

        assertThat(in.secret(KEY)).isNull();
        assertThat(in.problems()).singleElement().asString().doesNotContain(inline).doesNotContain(inFile);
        assertThat(LauncherLog.secrets(env, "EXERIS_DATABASE")).containsExactlyInAnyOrder(inline, inFile);
    }

    @Test
    @DisplayName("A path that is not a path is a refusal for the configuration and nothing for the redaction, which does not throw")
    void invalidPath() {
        Map<String, String> env = Map.of(KEY + "_FILE", "bad\u0000path");

        LauncherEnvironment in = new LauncherEnvironment(env);

        assertThat(in.secret(KEY)).isNull();
        assertThat(in.problems()).singleElement().asString().startsWith(KEY + "_FILE ").doesNotContain("bad");
        assertThat(LauncherLog.secrets(env, "EXERIS_DATABASE")).isEmpty();
    }
}
