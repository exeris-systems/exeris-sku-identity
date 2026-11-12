package eu.exeris.sku.identity.launcher;

import eu.exeris.kernel.spi.http.HttpConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import eu.exeris.sku.identity.support.TestConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The launcher reference lists, per command, the secrets its log withholds, and says what the redaction does.
 * Each row of the table is pinned to the settings the launcher reads for that command; each behaviour tested
 * end to end for a row is in {@link MigrateSecretsIT}, {@link ServeSecretsIT}, {@link ServeSecretsKernelBootIT}
 * and {@link BootstrapOwnerSecretsIT}. The statements about the kernel are checked against the kernel on the
 * class path.
 */
@DisplayName("The launcher documentation agrees with the launcher on secrets")
class LauncherSecretsDocumentationTest {

    private static final Path REFERENCE = Path.of("docs", "reference", "launcher.md");
    private static final Path EXPLANATION = Path.of("docs", "explanation", "launcher-stop-and-log-redaction.md");
    private static final Pattern SETTING = Pattern.compile("`(EXERIS_[A-Z_]+)`");
    private static final String W = LogRedaction.WITHHELD;

    private static String reference() throws IOException {
        return Files.readString(REFERENCE);
    }

    /** The rows of the table headed {@code Command | Secrets withheld}, command to the text of its row. */
    private static Map<String, String> secretsTable() throws IOException {
        Map<String, String> rows = new LinkedHashMap<>();
        boolean inTable = false;
        for (String line : Files.readAllLines(REFERENCE)) {
            if (line.startsWith("| Command | Secrets withheld |")) {
                inTable = true;
                continue;
            }
            if (inTable && line.startsWith("| ---")) {
                continue;
            }
            if (inTable && line.startsWith("|")) {
                String[] cells = line.split("\\|", -1);
                rows.put(cells[1].strip().replace("`", ""), cells[2].strip());
            } else if (inTable) {
                break;
            }
        }
        return rows;
    }

    private static Set<String> settingsIn(String text) {
        Set<String> found = new TreeSet<>();
        Matcher m = SETTING.matcher(text);
        while (m.find()) {
            found.add(m.group(1));
        }
        return found;
    }

    @Test
    @DisplayName("The table has one row for each command and no other")
    void rowsAreTheCommands() throws IOException {
        assertThat(secretsTable().keySet()).containsExactly("migrate", "serve", "bootstrap-owner");
    }

    @Test
    @DisplayName("migrate: the migration password and the service password are the settings the launcher reads, inline or from a file")
    void migrateRow() throws IOException {
        String row = secretsTable().get("migrate");

        assertThat(settingsIn(row)).containsExactlyInAnyOrder(Migrate.DATABASE_PREFIX + "_PASSWORD",
                StartupPlan.DATABASE_PREFIX + "_PASSWORD");
        assertThat(row).contains("_FILE");
        assertThat(learnt("migrate")).isEqualTo(Set.of(Migrate.DATABASE_PREFIX + "_PASSWORD",
                StartupPlan.DATABASE_PREFIX + "_PASSWORD"));
    }

    @Test
    @DisplayName("serve: the service password only")
    void serveRow() throws IOException {
        String row = secretsTable().get("serve");

        assertThat(row).isEqualTo("the service password");
        assertThat(learnt("serve")).isEqualTo(Set.of(StartupPlan.DATABASE_PREFIX + "_PASSWORD"));
    }

    @Test
    @DisplayName("bootstrap-owner: the service password and the content of the password file once read")
    void bootstrapOwnerRow() throws IOException {
        String row = secretsTable().get("bootstrap-owner");

        assertThat(row).contains("service password").contains("password file");
        assertThat(learnt("bootstrap-owner")).isEqualTo(Set.of(StartupPlan.DATABASE_PREFIX + "_PASSWORD"));
        assertThat(String.valueOf(LauncherLog.with(new String[0], "a-password-read-from-the-file".toCharArray())))
                .isNotEmpty();
    }

    /**
     * The settings whose value a command's launcher would withhold: every variable of both database prefixes
     * is set, and the settings whose values come back as secrets are returned. The migrate command's own
     * choice of prefixes is read through the method it uses.
     */
    private static Set<String> learnt(String command) {
        Map<String, String> env = new HashMap<>();
        Map<String, String> byValue = new HashMap<>();
        for (String prefix : List.of(Migrate.DATABASE_PREFIX, StartupPlan.DATABASE_PREFIX)) {
            String value = SecretForms.marker();
            env.put(prefix + "_PASSWORD", value);
            byValue.put(value, prefix + "_PASSWORD");
        }
        String[] secrets;
        try {
            if (command.equals("migrate")) {
                Method method = IdentitySkuApplication.class.getDeclaredMethod("secrets", Map.class);
                method.setAccessible(true);
                secrets = (String[]) method.invoke(null, env);
            } else {
                secrets = LauncherLog.secrets(env, StartupPlan.DATABASE_PREFIX);
            }
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
        return java.util.Arrays.stream(secrets).map(byValue::get).collect(Collectors.toSet());
    }

    @Test
    @DisplayName("The placeholders and the limits the reference names are the redaction's")
    void placeholdersAndLimits() throws IOException {
        String text = reference();

        assertThat(text).contains("`<withheld>`").contains("`(no message)`").contains("`(message withheld)`");
        assertThat(W).isEqualTo("<withheld>");
        assertThat(LogRedaction.of(null)).isEqualTo("(no message)");
        assertThat(text).contains("At most 8 distinct secrets").contains("shorter than 3 characters");
        assertThat(LogRedaction.MAXIMUM_SECRETS).isEqualTo(8);
        assertThat(LogRedaction.MINIMUM_SECRET_LENGTH).isEqualTo(3);
        String[] nine = new String[9];
        for (int i = 0; i < nine.length; i++) {
            nine[i] = SecretForms.marker();
        }
        assertThat(LogRedaction.of("failed " + nine[0], nine)).isEqualTo("(message withheld)");
    }

    @Test
    @DisplayName("The examples of percent-encoded spellings and of the rest-of-the-line rule behave as stated")
    void examples() throws IOException {
        String text = reference() + Files.readString(EXPLANATION);

        assertThat(text).contains("`a+b+c`, `a+b%2Bc` and `a%20b+c`");
        for (String spelled : List.of("a+b+c", "a+b%2Bc", "a%20b+c")) {
            assertThat(LogRedaction.of("refused " + spelled + " end", "a b+c")).as(spelled).isEqualTo("refused " + W + " end");
        }
        assertThat(LogRedaction.of("password=my secret pass")).isEqualTo("password=" + W);
        assertThat(LogRedaction.of("password=a,b")).isEqualTo("password=" + W);
        assertThat(LogRedaction.of("host=h password=p dbname=d")).isEqualTo("host=h password=" + W);
        assertThat(LogRedaction.of("{user=u, password=x, ssl=true}")).isEqualTo("{user=u, password=" + W);
        assertThat(LogRedaction.of("jdbc:postgresql://h:5432/db?password=x&ssl=true"))
                .isEqualTo("jdbc:postgresql://h:5432/db?password=" + W + "&ssl=true");
        assertThat(LogRedaction.of("jdbc:postgresql://u:x@h:5432/db")).isEqualTo("jdbc:postgresql://u:" + W + "@h:5432/db");
        assertThat(LogRedaction.of("Authorization: Bearer abc.def")).isEqualTo("Authorization: Bearer " + W);
        assertThat(LogRedaction.of("Set-Cookie: sid=abc; Path=/")).isEqualTo("Set-Cookie: " + W);
        assertThat(LogRedaction.of("run --password hunter2 now")).isEqualTo("run --password " + W + " now");
        assertThat(LogRedaction.of("monkey=banana keystore=k key_id=7")).isEqualTo("monkey=banana keystore=k key_id=7");
        assertThat(LogRedaction.of("at Name.java:42")).isEqualTo("at Name.java:42");
        assertThat(LogRedaction.of("authorization=abc cookie=abc -pabc")).isEqualTo("authorization=abc cookie=abc -pabc");
        assertThat(LogRedaction.of("password is hunter2")).isEqualTo("password is hunter2");
    }

    // --- the statements about the kernel and the stop ----------------------------------------------------

    @Test
    @DisplayName("The kernel's idle timeout is the idleTimeoutMillis of its HttpConfig, 30 000 ms by default, and the launcher does not set it")
    void idleTimeout() throws Exception {
        String text = reference() + Files.readString(EXPLANATION);

        assertThat(text).contains("`idleTimeoutMillis`").contains("`HttpConfig`").contains("30 000 ms");
        assertThat(java.util.Arrays.stream(HttpConfig.class.getRecordComponents()).map(c -> c.getName()))
                .contains("idleTimeoutMillis");
        assertThat(HttpConfig.DEFAULT_IDLE_TIMEOUT_MS).isEqualTo(30_000L);
        assertThat(HttpConfig.defaultServer().idleTimeoutMillis()).isEqualTo(30_000L);

        Map<String, String> env = TestConfig.env();
        env.put("EXERIS_ENVIRONMENT", "development");
        env.put("EXERIS_DATABASE_URL", "jdbc:postgresql://127.0.0.1:1/db");
        env.put("EXERIS_DATABASE_USER", "u");
        env.put("EXERIS_DATABASE_PASSWORD", "password-for-the-plan");
        StartupPlan plan = StartupPlan.prepare(env);
        assertThat(plan.kernelProperties().keySet()).noneMatch(key -> key.toLowerCase().contains("idle"));
    }

    @Test
    @DisplayName("The drain budget is 15 s and the stop grace the reference asks for (60 s) covers it and the idle timeout")
    void drainAndGrace() throws Exception {
        Field drain = IdentitySkuApplication.class.getDeclaredField("DRAIN");
        drain.setAccessible(true);
        String text = reference();

        assertThat((Duration) drain.get(null)).isEqualTo(Duration.ofSeconds(15));
        assertThat(text).contains("one budget of 15 s").contains("at least 60 s").contains("TimeoutStopSec=60");
        assertThat(Duration.ofSeconds(15).plusMillis(HttpConfig.DEFAULT_IDLE_TIMEOUT_MS)).isLessThanOrEqualTo(Duration.ofSeconds(60));
    }

    @Test
    @DisplayName("Every settings name the reference's secrets sections mention is one the launcher reads")
    void namedSettingsExist(@TempDir Path dir) throws IOException {
        String text = reference();
        String section = text.substring(text.indexOf("### Secrets in the launcher's output"), text.indexOf("## `bootstrap-owner`"));
        List<String> known = new ArrayList<>(List.of(Migrate.DATABASE_PREFIX + "_PASSWORD", StartupPlan.DATABASE_PREFIX + "_PASSWORD"));

        assertThat(settingsIn(section)).isSubsetOf(known);
    }
}
