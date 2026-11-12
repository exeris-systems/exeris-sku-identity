package eu.exeris.sku.identity.config;

import eu.exeris.sku.identity.support.TestConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * A message about a refused setting names the setting, a line number or a bound, and never repeats a value, a
 * path or a line of a file. Each site that can refuse is driven with a marker of its own in the position an
 * operator controls, and neither the marker nor any six consecutive characters of it may appear in the message.
 */
@DisplayName("IdentityConfig: a refusal names the setting, a line or a bound, never the value")
class IdentityConfigMessagesTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    private static String marker() {
        StringBuilder value = new StringBuilder("Mq");
        while (value.length() < 20) {
            value.append(ALNUM.charAt(RANDOM.nextInt(ALNUM.length())));
        }
        return value.toString();
    }

    private static String numericMarker() {
        StringBuilder value = new StringBuilder("7");
        while (value.length() < 15) {
            value.append((char) ('0' + RANDOM.nextInt(10)));
        }
        return value.toString();
    }

    private static Map<String, String> env(String... kv) {
        Map<String, String> m = new HashMap<>(TestConfig.env());
        for (int i = 0; i < kv.length; i += 2) {
            if (kv[i + 1] == null) {
                m.remove(kv[i]);
            } else {
                m.put(kv[i], kv[i + 1]);
            }
        }
        return m;
    }

    /** The whole text a refusal offers: the exception message and each problem. */
    private static String refusal(Map<String, String> environment) {
        IdentityConfigException failure = (IdentityConfigException) catchThrowable(environment);
        List<String> parts = new ArrayList<>(failure.problems());
        parts.add(failure.getMessage());
        return String.join("\n", parts);
    }

    private static Throwable catchThrowable(Map<String, String> environment) {
        Throwable[] caught = new Throwable[1];
        assertThatThrownBy(() -> {
            try {
                IdentityConfig.load(environment);
            } catch (Throwable t) {
                caught[0] = t;
                throw t;
            }
        }).isInstanceOf(IdentityConfigException.class);
        return caught[0];
    }

    private static void assertNoPieceOf(String text, String marker, String where) {
        assertThat(text).as(where).doesNotContain(marker);
        for (int i = 0; i + 6 <= marker.length(); i++) {
            assertThat(text).as(where + ", piece " + marker.substring(i, i + 6)).doesNotContain(marker.substring(i, i + 6));
        }
    }

    // --- numbers ---------------------------------------------------------------------------------------

    private static List<String> numericKeys() {
        List<String> keys = new ArrayList<>(List.of(
                "EXERIS_HTTP_PORT", "EXERIS_HTTP_MAX_REQUEST_BODY_BYTES", "EXERIS_HTTP_MAX_REQUEST_HEADER_COUNT",
                "EXERIS_HTTP_MAX_REQUEST_HEADER_SIZE", "EXERIS_JWT_CLOCK_SKEW_SECONDS", "EXERIS_RATELIMIT_MAX_KEYS",
                "EXERIS_CREDENTIALS_LOCKOUT_MAX_ATTEMPTS", "EXERIS_CREDENTIALS_LOCKOUT_FAILURE_WINDOW_SECONDS",
                "EXERIS_CREDENTIALS_LOCKOUT_DURATION_SECONDS",
                "EXERIS_CREDENTIALS_TOKEN_VERIFICATION_VALIDITY_SECONDS",
                "EXERIS_CREDENTIALS_TOKEN_RESET_VALIDITY_SECONDS", "EXERIS_CREDENTIALS_TOKEN_ISSUE_COOLDOWN_SECONDS",
                "EXERIS_CREDENTIALS_PASSWORD_MIN_LENGTH", "EXERIS_CREDENTIALS_PASSWORD_MAX_LENGTH",
                "EXERIS_PASSWORD_ARGON2_MEMORY_KIB", "EXERIS_PASSWORD_ARGON2_ITERATIONS",
                "EXERIS_PASSWORD_ARGON2_PARALLELISM"));
        for (String group : List.of("LOGIN", "REFRESH", "PASSWORD_RESET", "VERIFICATION", "INVITATION_ACCEPT")) {
            keys.add("EXERIS_RATELIMIT_" + group + "_CAPACITY");
            keys.add("EXERIS_RATELIMIT_" + group + "_REFILL_SECONDS");
        }
        return keys;
    }

    @Test
    @DisplayName("A number that is out of range, negative, not a number or too large for a long is refused by its setting and its bounds")
    void numbers() {
        for (String key : numericKeys()) {
            for (String value : List.of(numericMarker(), "-" + numericMarker(), marker(), "9".repeat(30) + numericMarker())) {
                String text = refusal(env(key, value));

                assertThat(text).as(key).contains(key + " must be ");
                assertNoPieceOf(text, value.replace("-", ""), key + "=" + "<value>");
            }
            assertThat(refusal(env(key, "-1"))).as(key).containsPattern(key + " must be (between \\d+ and \\d+|a whole number)");
        }
    }

    @Test
    @DisplayName("A duration that is not ISO-8601, or not positive, and a TTL above its maximum are refused by setting")
    void durations() {
        for (String key : List.of("EXERIS_MFA_TOTP_CHALLENGE_TTL", "EXERIS_MFA_TOTP_CHALLENGE_MAX_TTL")) {
            String value = marker();
            String text = refusal(env(key, value));

            assertThat(text).contains(key + " must be ");
            assertNoPieceOf(text, value, key);
        }
        assertThat(refusal(env("EXERIS_MFA_TOTP_CHALLENGE_TTL", "PT20M", "EXERIS_MFA_TOTP_CHALLENGE_MAX_TTL", "PT1M")))
                .contains("EXERIS_MFA_TOTP_CHALLENGE_TTL must not exceed EXERIS_MFA_TOTP_CHALLENGE_MAX_TTL");
        assertThat(refusal(env("EXERIS_MFA_TOTP_CHALLENGE_TTL", "-PT5M"))).contains("must be a positive");
    }

    // --- the capabilities' settings --------------------------------------------------------------------

    @Test
    @DisplayName("A token issuer setting the capability refuses is named, its value is not")
    void tokenIssuerSettings() {
        for (String name : List.of("TOKEN_TTL", "MAX_TOKEN_TTL", "CLOCK_SKEW", "KEY_TTL", "ROTATION_CHECK_INTERVAL",
                "JWKS_MAX_AGE", "MANUAL_ROTATION")) {
            String key = "EXERIS_TOKEN_ISSUER_" + name;
            String value = marker();

            String text = refusal(env(key, value));

            assertThat(text).as(key).contains("token issuer settings are not usable").contains(key);
            assertNoPieceOf(text, value, key);
        }
        String issuer = marker();
        assertThat(refusal(env("EXERIS_JWT_ISSUER", issuer))).contains("EXERIS_JWT_ISSUER must equal");
        assertNoPieceOf(refusal(env("EXERIS_JWT_ISSUER", issuer, "EXERIS_JWT_AUDIENCE", issuer)), issuer, "jwt");
    }

    @Test
    @DisplayName("A CORS origin that is refused is named by its position, never by its text")
    void corsOrigins() {
        String marker = marker();
        String text = refusal(env("EXERIS_CORS_ALLOWED_ORIGINS", marker + ",https://user:" + marker + "@x.example,*,"
                + "https://ok.example/" + marker + ",http://[" + marker + "]"));

        assertThat(text).contains("EXERIS_CORS_ALLOWED_ORIGINS: entry 1 ").contains("entry 2 ");
        assertNoPieceOf(text, marker, "cors");
    }

    @Test
    @DisplayName("The rate-limit, password-length and MFA cross-field failures name settings only")
    void crossFieldFailures() {
        String header = "bad header " + marker();
        String text = refusal(env("EXERIS_RATELIMIT_FORWARDED_HEADER", header));
        assertThat(text).contains("rate limiting is not usable: check EXERIS_RATELIMIT_TRUSTED_PROXIES and "
                + "EXERIS_RATELIMIT_FORWARDED_HEADER");
        assertNoPieceOf(text, header, "forwarded header");

        text = refusal(env("EXERIS_CREDENTIALS_PASSWORD_MIN_LENGTH", "4093", "EXERIS_CREDENTIALS_PASSWORD_MAX_LENGTH",
                "4091"));
        assertThat(text).contains("password length is not usable: check EXERIS_CREDENTIALS_PASSWORD_MIN_LENGTH and "
                + "EXERIS_CREDENTIALS_PASSWORD_MAX_LENGTH").doesNotContain("4093").doesNotContain("4091");
    }

    @Test
    @DisplayName("The lockout, token-validity and Argon2 settings cannot be combined into a refusal that repeats a value: every extreme of their bounds either loads or names settings")
    void lockoutTokenAndArgon2Extremes() {
        List<String[]> groups = List.of(
                new String[]{"EXERIS_CREDENTIALS_LOCKOUT_MAX_ATTEMPTS", "1", "1000"},
                new String[]{"EXERIS_CREDENTIALS_LOCKOUT_FAILURE_WINDOW_SECONDS", "1", "315360000"},
                new String[]{"EXERIS_CREDENTIALS_LOCKOUT_DURATION_SECONDS", "1", "315360000"},
                new String[]{"EXERIS_CREDENTIALS_TOKEN_VERIFICATION_VALIDITY_SECONDS", "1", "315360000"},
                new String[]{"EXERIS_CREDENTIALS_TOKEN_RESET_VALIDITY_SECONDS", "1", "315360000"},
                new String[]{"EXERIS_CREDENTIALS_TOKEN_ISSUE_COOLDOWN_SECONDS", "1", "315360000"},
                new String[]{"EXERIS_PASSWORD_ARGON2_MEMORY_KIB", "8192", "4194304"},
                new String[]{"EXERIS_PASSWORD_ARGON2_ITERATIONS", "1", "100"},
                new String[]{"EXERIS_PASSWORD_ARGON2_PARALLELISM", "1", "64"});
        for (int mask = 0; mask < (1 << groups.size()); mask++) {
            Map<String, String> environment = env();
            StringBuilder values = new StringBuilder();
            for (int i = 0; i < groups.size(); i++) {
                String value = groups.get(i)[1 + ((mask >> i) & 1)];
                environment.put(groups.get(i)[0], value);
                values.append(value).append(' ');
            }
            try {
                IdentityConfig.load(environment);
            } catch (IdentityConfigException refused) {
                assertThat(refusal(environment)).as(values.toString()).doesNotContainPattern("\\d{4,}");
            }
        }
    }

    // --- files named by a setting ----------------------------------------------------------------------

    @Test
    @DisplayName("A _FILE setting that names a file that cannot be read, or names it together with the inline value, is refused by setting, without the path")
    void fileSettings(@TempDir Path dir) throws IOException {
        Map<String, String> pairs = new java.util.LinkedHashMap<>();
        pairs.put("EXERIS_TOKEN_ISSUER_KEKS", "EXERIS_TOKEN_ISSUER_KEKS_FILE");
        pairs.put("EXERIS_MFA_TOTP_KEKS", "EXERIS_MFA_TOTP_KEKS_FILE");
        pairs.put("EXERIS_MFA_TOTP_PEPPER", "EXERIS_MFA_TOTP_PEPPER_FILE");
        pairs.put("EXERIS_FEDERATED_LOGIN_STATE_KEYS", "EXERIS_FEDERATED_LOGIN_STATE_KEYS_FILE");
        for (Map.Entry<String, String> pair : pairs.entrySet()) {
            String marker = marker();
            Path directory = Files.createDirectory(dir.resolve("d-" + marker));
            for (String value : List.of(dir.resolve("missing-" + marker).toString(), directory.toString(),
                    "bad\u0000" + marker, marker)) {
                String text = refusal(env(pair.getKey(), null, pair.getValue(), value));

                assertThat(text).contains(pair.getValue() + " names a file that cannot be read.");
                assertNoPieceOf(text, marker, pair.getValue());
            }
            String text = refusal(env(pair.getValue(), dir.resolve("f-" + marker).toString()));
            assertThat(text).contains("set either " + pair.getKey() + " or " + pair.getValue() + ", not both");
            assertNoPieceOf(text, marker, pair.getValue() + " with the inline value");
        }
    }

    @Test
    @DisplayName("EXERIS_IDENTITY_CONFIG naming a missing file, a directory or an invalid path is refused by the setting, without the path")
    void configFileSetting(@TempDir Path dir) throws IOException {
        String marker = marker();
        Path directory = Files.createDirectory(dir.resolve("d-" + marker));
        for (String value : List.of(dir.resolve("missing-" + marker).toString(), directory.toString(),
                "bad\u0000" + marker, marker)) {
            String text = refusal(env("EXERIS_IDENTITY_CONFIG", value));

            assertThat(text).contains("EXERIS_IDENTITY_CONFIG names a file that cannot be read.");
            assertNoPieceOf(text, marker, "EXERIS_IDENTITY_CONFIG");
        }
    }

    private static final Pattern LINE_PROBLEM = Pattern.compile(
            "EXERIS_IDENTITY_CONFIG line \\d+ (is not a setting\\.|is not a valid line of a properties file\\.|"
                    + "carries an unknown setting: EXERIS_[A-Z0-9_]{0,80})");

    private static String refusalOfFile(Path dir, String... lines) throws IOException {
        Path file = Files.write(Files.createTempFile(dir, "identity-", ".properties"),
                String.join("\n", lines).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return refusal(env("EXERIS_IDENTITY_CONFIG", file.toString()));
    }

    private static List<String> lineProblems(Path dir, String... lines) throws IOException {
        Path file = Files.write(Files.createTempFile(dir, "identity-", ".properties"),
                String.join("\n", lines).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return ((IdentityConfigException) catchThrowable(env("EXERIS_IDENTITY_CONFIG", file.toString()))).problems();
    }

    @Test
    @DisplayName("A line of the file that is a bare marker, has a key in lower case or with punctuation, or is a malformed escape is refused by its line number, without the line")
    void fileLines(@TempDir Path dir) throws IOException {
        String marker = marker();
        String longKey = "EXERIS_" + "A".repeat(100);

        List<String> problems = lineProblems(dir,
                "# a comment",
                marker,
                "lower_" + marker + "=1",
                "EXERIS_HTTP_PORT-" + marker + "=1",
                "EXERIS_HTTP_PORT=\\uZZZZ" + marker,
                "EXERIS_NO_SUCH_SETTING=" + marker,
                longKey + "=" + marker,
                "key with spaces " + marker + "=1",
                "EXERISé" + marker + "=1");

        assertThat(problems).hasSize(8).allSatisfy(problem -> assertThat(problem).matches(LINE_PROBLEM));
        assertThat(problems.get(0)).isEqualTo("EXERIS_IDENTITY_CONFIG line 2 is not a setting.");
        assertThat(problems.get(1)).isEqualTo("EXERIS_IDENTITY_CONFIG line 3 is not a setting.");
        assertThat(problems.get(2)).isEqualTo("EXERIS_IDENTITY_CONFIG line 4 is not a setting.");
        assertThat(problems.get(3)).isEqualTo("EXERIS_IDENTITY_CONFIG line 5 is not a valid line of a properties file.");
        assertThat(problems.get(4)).isEqualTo("EXERIS_IDENTITY_CONFIG line 6 carries an unknown setting: EXERIS_NO_SUCH_SETTING");
        assertThat(problems.get(5)).isEqualTo("EXERIS_IDENTITY_CONFIG line 7 is not a setting.");
        String all = String.join("\n", problems);
        assertNoPieceOf(all, marker, "file lines");
        assertThat(all).doesNotContain(longKey.substring(0, 20 + 7));
    }

    @Test
    @DisplayName("A continuation line that carries a marker is reported by the line it starts on, and a value built from it is reported by setting")
    void continuationLines(@TempDir Path dir) throws IOException {
        String marker = marker();

        List<String> unknown = lineProblems(dir, "# first", "EXERIS_NO\\", marker + "=1");
        String value = refusalOfFile(dir, "EXERIS_HTTP_PORT=8\\", marker);

        assertThat(unknown).containsExactly("EXERIS_IDENTITY_CONFIG line 2 is not a setting.");
        assertThat(value).contains("EXERIS_HTTP_PORT must be a whole number");
        assertNoPieceOf(String.join("\n", unknown) + value, marker, "continuation");
    }

    @Test
    @DisplayName("A comment that ends in a backslash does not swallow the next line, and its text is never printed")
    void commentEndingInBackslash(@TempDir Path dir) throws IOException {
        String marker = marker();
        Path file = Files.writeString(dir.resolve("identity.properties"), "# note " + marker + " \\\nEXERIS_HTTP_PORT=9\n"
                + "! another " + marker + "\\\nEXERIS_HTTP_MAX_REQUEST_HEADER_COUNT=7\n");

        IdentityConfig config = IdentityConfig.load(env("EXERIS_IDENTITY_CONFIG", file.toString()));

        assertThat(config.http().port()).isEqualTo(9);
        assertThat(config.http().maxRequestHeaderCount()).isEqualTo(7);
    }

    @Test
    @DisplayName("A known setting given the marker in the file is reported by setting; an unknown setting named EXERIS_ and capitals is reported by key only")
    void valueInTheFile(@TempDir Path dir) throws IOException {
        String marker = marker();

        String text = refusalOfFile(dir, "EXERIS_HTTP_PORT=" + marker);

        assertThat(text).contains("EXERIS_HTTP_PORT must be a whole number");
        assertNoPieceOf(text, marker, "value in file");
    }
}
