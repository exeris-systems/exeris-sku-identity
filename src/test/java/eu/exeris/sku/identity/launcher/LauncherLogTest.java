package eu.exeris.sku.identity.launcher;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assumptions.assumeThat;

@DisplayName("LauncherLog")
class LauncherLogTest {

    private static final String PREFIX = "EXERIS_X";

    /** A logger that keeps what it is given. */
    private static final class Recording implements System.Logger {
        final List<String> formats = new ArrayList<>();
        final List<Object[]> arguments = new ArrayList<>();
        final List<Level> levels = new ArrayList<>();

        @Override
        public String getName() {
            return "recording";
        }

        @Override
        public boolean isLoggable(Level level) {
            return true;
        }

        @Override
        public void log(Level level, ResourceBundle bundle, String msg, Throwable thrown) {
            throw new AssertionError("a throwable must never be handed to the logger");
        }

        @Override
        public void log(Level level, ResourceBundle bundle, String format, Object... params) {
            levels.add(level);
            formats.add(format);
            arguments.add(params);
        }
    }

    private static Map<String, String> env(String... keyValues) {
        Map<String, String> env = new HashMap<>();
        for (int i = 0; i < keyValues.length; i += 2) {
            env.put(keyValues[i], keyValues[i + 1]);
        }
        return env;
    }

    // --- log -------------------------------------------------------------------------------------------

    @Test
    @DisplayName("Every foreign argument is redacted with every secret and the level and constant format pass unchanged")
    void everyArgumentWithEverySecret() {
        String first = SecretForms.marker();
        String second = SecretForms.marker();
        Recording logger = new Recording();

        LauncherLog.log(logger, System.Logger.Level.ERROR, "failed {0} / {1}", new String[]{first, second},
                "one " + first + " and " + second, "two " + second + " and " + first);

        assertThat(logger.levels).containsExactly(System.Logger.Level.ERROR);
        assertThat(logger.formats).containsExactly("failed {0} / {1}");
        assertThat(logger.arguments.getFirst()).hasSize(2);
        for (Object argument : logger.arguments.getFirst()) {
            assertThat(argument.toString()).doesNotContain(first).doesNotContain(second).contains("<withheld>");
        }
    }

    @Test
    @DisplayName("The constant format is never treated as foreign text, even when it holds a secret")
    void formatIsNotRedacted() {
        String format = "Migration configuration refused: {0}";
        Recording logger = new Recording();

        LauncherLog.log(logger, System.Logger.Level.ERROR, format, new String[]{"Migration configuration"},
                "a message about Migration configuration");

        assertThat(logger.formats).containsExactly(format);
        assertThat(logger.arguments.getFirst()[0].toString()).doesNotContain("Migration configuration");
    }

    @Test
    @DisplayName("A null foreign text is logged as no message and a call without foreign text logs the format alone")
    void nullAndNone() {
        Recording logger = new Recording();

        LauncherLog.log(logger, System.Logger.Level.WARNING, "x {0}", new String[0], (String) null);
        LauncherLog.log(logger, System.Logger.Level.INFO, "constant", new String[]{"abcdef"});

        assertThat(logger.arguments.get(0)[0]).isEqualTo("(no message)");
        assertThat(logger.arguments.get(1)).isEmpty();
        assertThat(logger.formats).containsExactly("x {0}", "constant");
    }

    @Test
    @DisplayName("A secret reaches the logger in no spelling: percent-encoded and Base64 forms of it are withheld too")
    void encodedForms() {
        String secret = SecretForms.markerWithSpecials();
        Recording logger = new Recording();
        List<String> forms = SecretForms.contiguousForms(secret);

        for (String form : forms) {
            LauncherLog.log(logger, System.Logger.Level.ERROR, "m {0}", new String[]{secret}, "driver said " + form);
        }

        assertThat(forms).hasSizeGreaterThan(5);
        for (int i = 0; i < forms.size(); i++) {
            assertThat(logger.arguments.get(i)[0].toString()).as("form " + i + " of length " + forms.get(i).length())
                    .doesNotContain(forms.get(i));
        }
    }

    // --- secrets(env, prefixes) ------------------------------------------------------------------------

    @Test
    @DisplayName("An inline password is a secret")
    void inline() {
        String secret = SecretForms.marker();

        assertThat(LauncherLog.secrets(env(PREFIX + "_PASSWORD", secret), PREFIX)).containsExactly(secret);
    }

    @Test
    @DisplayName("A password from a file is a secret, without its trailing line breaks, as the configuration reads it")
    void fromFile(@TempDir Path dir) throws IOException {
        String secret = SecretForms.marker();
        for (String ending : List.of("", "\n", "\r\n", "\n\n\r\n")) {
            Path file = Files.writeString(dir.resolve("p" + ending.length()), secret + ending);
            Map<String, String> env = env(PREFIX + "_PASSWORD_FILE", file.toString());

            String[] known = LauncherLog.secrets(env, PREFIX);
            LauncherEnvironment in = new LauncherEnvironment(env);
            String configured = in.secret(PREFIX + "_PASSWORD");

            assertThat(in.problems()).isEmpty();
            assertThat(configured).isEqualTo(secret);
            assertThat(known).as("ending " + ending.length()).containsExactly(configured);
        }
    }

    @Test
    @DisplayName("A line break inside the password and a trailing space stay part of the secret, as in the configuration")
    void interiorBreaksAndSpacesAgree(@TempDir Path dir) throws IOException {
        String secret = SecretForms.marker(14) + "\nsecond line " + SecretForms.marker(14) + " ";
        Path file = Files.writeString(dir.resolve("p"), secret + "\n");
        Map<String, String> env = env(PREFIX + "_PASSWORD_FILE", file.toString());
        LauncherEnvironment in = new LauncherEnvironment(env);

        String configured = in.secret(PREFIX + "_PASSWORD");

        assertThat(LauncherLog.secrets(env, PREFIX)).containsExactly(configured).containsExactly(secret);
    }

    @Test
    @DisplayName("The path of the file is trimmed as the configuration trims it")
    void pathIsTrimmed(@TempDir Path dir) throws IOException {
        String secret = SecretForms.marker();
        Path file = Files.writeString(dir.resolve("p"), secret);
        Map<String, String> env = env(PREFIX + "_PASSWORD_FILE", "  " + file + "  ");

        assertThat(LauncherLog.secrets(env, PREFIX)).containsExactly(secret);
        assertThat(new LauncherEnvironment(env).secret(PREFIX + "_PASSWORD")).isEqualTo(secret);
    }

    @Test
    @DisplayName("Inline and file together are both secrets, although the configuration refuses the pair")
    void both(@TempDir Path dir) throws IOException {
        String inline = SecretForms.marker();
        String inFile = SecretForms.marker();
        Path file = Files.writeString(dir.resolve("p"), inFile);

        assertThat(LauncherLog.secrets(env(PREFIX + "_PASSWORD", inline, PREFIX + "_PASSWORD_FILE", file.toString()),
                PREFIX)).containsExactlyInAnyOrder(inline, inFile);
    }

    @Test
    @DisplayName("Neither setting, a blank file name or an empty inline value give no secret")
    void neither() {
        assertThat(LauncherLog.secrets(env(), PREFIX)).isEmpty();
        assertThat(LauncherLog.secrets(env(PREFIX + "_PASSWORD", ""), PREFIX)).isEmpty();
        assertThat(LauncherLog.secrets(env(PREFIX + "_PASSWORD_FILE", "   "), PREFIX)).isEmpty();
    }

    @Test
    @DisplayName("A missing file, an empty file, a file of line breaks, a directory and a file that is not UTF-8 give no secret and never throw")
    void unusableFiles(@TempDir Path dir) throws IOException {
        Path empty = Files.writeString(dir.resolve("empty"), "");
        Path breaks = Files.writeString(dir.resolve("breaks"), "\n\r\n");
        Path binary = dir.resolve("binary");
        Files.write(binary, new byte[]{(byte) 0xC3, (byte) 0x28, (byte) 0xFF, (byte) 0xFE, 'a', 'b', 'c'});

        for (Path path : List.of(dir.resolve("absent"), empty, breaks, dir, binary)) {
            Map<String, String> env = env(PREFIX + "_PASSWORD_FILE", path.toString());
            assertThatCode(() -> LauncherLog.secrets(env, PREFIX)).doesNotThrowAnyException();
            assertThat(LauncherLog.secrets(env, PREFIX)).as(path.getFileName().toString()).isEmpty();
        }
    }

    @Test
    @DisplayName("A file the process may not read gives no secret and never throws")
    void unreadable(@TempDir Path dir) throws IOException {
        Path file = Files.writeString(dir.resolve("locked"), SecretForms.marker());
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("---------"));
        assumeThat(Files.isReadable(file)).as("running as a user the mode binds").isFalse();

        assertThat(LauncherLog.secrets(env(PREFIX + "_PASSWORD_FILE", file.toString()), PREFIX)).isEmpty();
    }

    @Test
    @DisplayName("A name that is not a path, a null environment and a null value never throw")
    void neverThrows() {
        assertThatCode(() -> LauncherLog.secrets(env(PREFIX + "_PASSWORD_FILE", "a\0b"), PREFIX))
                .doesNotThrowAnyException();
        assertThatCode(() -> LauncherLog.secrets(null, PREFIX)).doesNotThrowAnyException();
        assertThat(LauncherLog.secrets(null, PREFIX)).isEmpty();
        Map<String, String> withNull = new HashMap<>();
        withNull.put(PREFIX + "_PASSWORD", null);
        withNull.put(PREFIX + "_PASSWORD_FILE", null);
        assertThat(LauncherLog.secrets(withNull, PREFIX)).isEmpty();
        assertThat(LauncherLog.secrets(env(PREFIX + "_PASSWORD", "x"))).isEmpty();
    }

    @Test
    @DisplayName("A named pipe is not read and the call returns at once")
    @Timeout(value = 20, unit = TimeUnit.SECONDS)
    void fifo(@TempDir Path dir) throws Exception {
        Path pipe = dir.resolve("pipe");
        Process made = new ProcessBuilder("mkfifo", pipe.toString()).redirectErrorStream(true).start();
        assumeThat(made.waitFor(5, TimeUnit.SECONDS) && made.exitValue() == 0).as("mkfifo available").isTrue();

        String[] found = LauncherLog.secrets(env(PREFIX + "_PASSWORD_FILE", pipe.toString()), PREFIX);

        assertThat(found).isEmpty();
    }

    @Test
    @DisplayName("A file larger than any password is a secret exactly when the configuration reads it as the password")
    void veryLargeFile(@TempDir Path dir) throws IOException {
        String secret = SecretForms.marker(24) + "x".repeat(200 * 1024);
        Path file = Files.writeString(dir.resolve("large"), secret + "\n", StandardCharsets.UTF_8);
        Map<String, String> env = env(PREFIX + "_PASSWORD_FILE", file.toString());
        LauncherEnvironment in = new LauncherEnvironment(env);

        String configured = in.secret(PREFIX + "_PASSWORD");

        assertThat(configured != null).as("the configuration reads the file").isTrue();
        assertThat(List.of(LauncherLog.secrets(env, PREFIX)).contains(configured))
                .as("the configuration uses the file's content (" + configured.length()
                        + " characters) as the password, so the log must withhold it").isTrue();
    }

    @Test
    @DisplayName("Several prefixes add their secrets in order and an unrelated prefix adds none")
    void prefixes() {
        String a = SecretForms.marker();
        String b = SecretForms.marker();

        assertThat(LauncherLog.secrets(env("A_PASSWORD", a, "B_PASSWORD", b, "C_PASSWORD", "other"), "A", "B"))
                .containsExactly(a, b);
    }

    // --- secrets(database), with ---------------------------------------------------------------------

    @Test
    @DisplayName("The secrets of a plan's database are its password, and none for no database")
    void ofDatabase() {
        String secret = SecretForms.marker();

        assertThat(LauncherLog.secrets(new DatabaseSettings("jdbc:postgresql://h/d", "u", secret)))
                .containsExactly(secret);
        assertThat(LauncherLog.secrets((DatabaseSettings) null)).isEmpty();
    }

    @Test
    @DisplayName("with adds the content of a character array as one more secret, leaves the given array alone, and adds nothing for none")
    void withPassword() {
        String known = SecretForms.marker();
        String owner = SecretForms.marker();
        String[] base = {known};

        String[] all = LauncherLog.with(base, owner.toCharArray());

        assertThat(all).containsExactly(known, owner);
        assertThat(base).containsExactly(known);
        assertThat(LauncherLog.with(base, null)).containsExactly(known);
        assertThat(LauncherLog.with(base, new char[0])).containsExactly(known);
        assertThat(LauncherLog.with(new String[0], owner.toCharArray())).containsExactly(owner);
    }

    @Test
    @DisplayName("A secret added with a character array is withheld by log")
    void withThenLog() {
        String owner = SecretForms.marker();
        Recording logger = new Recording();

        LauncherLog.log(logger, System.Logger.Level.ERROR, "m {0}",
                LauncherLog.with(new String[0], owner.toCharArray()), "the file held " + owner);

        assertThat(logger.arguments.getFirst()[0].toString()).doesNotContain(owner);
    }

    @Test
    @DisplayName("A kernel failure whose message quotes the connection URL is logged with the password and the credentials of the URL withheld; this is the seam a real kernel does not reach, because its persistence failure carries no URL")
    void kernelMessageQuotingTheUrl() {
        String configured = SecretForms.markerWithSpecials();
        String inUrl = SecretForms.marker();
        Recording logger = new Recording();
        String message = "Subsystem 'persistence' failed: could not open jdbc:postgresql://u:" + inUrl
                + "@db.example.test:5432/identity?ssl=true&password=" + java.net.URLEncoder.encode(configured,
                StandardCharsets.UTF_8) + " using " + configured;

        LauncherLog.log(logger, System.Logger.Level.ERROR, "The kernel did not boot, nothing was started: {0}",
                LauncherLog.secrets(new DatabaseSettings("jdbc:postgresql://h/d", "u", configured)), message);

        String logged = logger.arguments.getFirst()[0].toString();
        assertThat(logged).contains("db.example.test:5432/identity").contains("ssl=true");
        SecretForms.assertNoLeaks(logged, "kernel message", Map.of("URL", inUrl, "PASSWORD", configured));
    }
}
