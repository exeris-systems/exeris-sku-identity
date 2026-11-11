package eu.exeris.sku.identity.launcher;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.SecureRandom;
import java.time.Duration;
import java.util.List;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

@DisplayName("LogRedaction")
class LogRedactionTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String W = LogRedaction.WITHHELD;
    private static final String ALPHANUMERIC = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    /** A value that appears nowhere else in a message. */
    private static String random() {
        StringBuilder value = new StringBuilder("v");
        for (int i = 0; i < 14; i++) {
            value.append(ALPHANUMERIC.charAt(RANDOM.nextInt(ALPHANUMERIC.length())));
        }
        return value.toString();
    }

    @Test
    @DisplayName("A URL with a password in its authority and in a parameter shows neither and keeps the rest")
    void authorityAndParameter() {
        String secret = random();
        String message = "connect to jdbc:postgresql://u:" + secret + "@h/d?password=" + secret + "&ssl=true failed";

        String safe = LogRedaction.of(message, secret);

        assertThat(safe).doesNotContain(secret)
                .isEqualTo("connect to jdbc:postgresql://u:" + W + "@h/d?password=" + W + "&ssl=true failed");
    }

    @Test
    @DisplayName("The patterns withhold both occurrences without being told the secret")
    void patternsAloneWithholdBoth() {
        String secret = random();

        String safe = LogRedaction.of("jdbc:postgresql://u:" + secret + "@h/d?password=" + secret + "&ssl=true");

        assertThat(safe).doesNotContain(secret).contains("u:", "@h/d", "ssl=true");
    }

    @ParameterizedTest
    @ValueSource(strings = {"password", "passwd", "pwd", "sslpassword", "secret", "token"})
    @DisplayName("Each secret parameter name is withheld, in any case, before '&', before ';' and at the end")
    void parameterNames(String name) {
        for (String spelled : List.of(name, name.toUpperCase(), Character.toUpperCase(name.charAt(0)) + name.substring(1))) {
            String value = random();

            String beforeAmpersand = LogRedaction.of("x?" + spelled + "=" + value + "&ssl=true");
            String beforeSemicolon = LogRedaction.of("x;" + spelled + "=" + value + ";next=1");
            String atEnd = LogRedaction.of("x?a=1&" + spelled + "=" + value);

            assertThat(beforeAmpersand).as(spelled).doesNotContain(value).endsWith("&ssl=true");
            assertThat(beforeSemicolon).as(spelled).doesNotContain(value).endsWith(";next=1");
            assertThat(atEnd).as(spelled).doesNotContain(value).startsWith("x?a=1&");
        }
    }

    @Test
    @DisplayName("A URL-encoded value is withheld whole")
    void urlEncodedValue() {
        String tail = random();
        String encoded = "p%40ss%2F%26" + tail;

        String safe = LogRedaction.of("jdbc:postgresql://h/d?password=" + encoded + "&ssl=true");

        assertThat(safe).doesNotContain(tail).doesNotContain("p%40ss").endsWith("&ssl=true");
    }

    @ParameterizedTest
    @ValueSource(strings = {"'", "\""})
    @DisplayName("A quoted value is withheld")
    void quotedValue(String quote) {
        String value = random();

        String safe = LogRedaction.of("options password=" + quote + value + quote + " ssl=true");

        assertThat(safe).doesNotContain(value).contains("ssl=true");
    }

    @ParameterizedTest
    @ValueSource(strings = {"'", "\""})
    @DisplayName("A quoted value that holds a space is withheld whole")
    void quotedValueWithASpace(String quote) {
        String first = random();
        String second = random();

        String safe = LogRedaction.of("options password=" + quote + first + " " + second + quote + " ssl=true");

        assertThat(safe).doesNotContain(first).doesNotContain(second).contains("ssl=true");
    }

    @ParameterizedTest
    @ValueSource(strings = {"a.b*c+d?e(f)[g]{h}|i^j", "x$1y$0z", "back\\slash\\\\", "(?i)(a+)+$", "a@b", "a:b", "a/b",
            "a&b", "p@ss:w/rd&x$y\\z"})
    @DisplayName("A configured secret made of metacharacters is withheld wherever it appears, as a literal")
    void secretWithMetacharacters(String secret) {
        String message = "first " + secret + " middle " + secret + " last";

        String safe = LogRedaction.of(message, secret);

        assertThat(safe).isEqualTo("first " + W + " middle " + W + " last");
    }

    @Test
    @DisplayName("A configured secret that holds '&' is withheld whole inside a parameter")
    void secretWithAmpersandInAParameter() {
        String head = random();
        String tail = random();
        String secret = head + "&" + tail;

        String safe = LogRedaction.of("jdbc:postgresql://h/d?password=" + secret + "&ssl=true", secret);

        assertThat(safe).doesNotContain(head).doesNotContain(tail).endsWith("&ssl=true");
    }

    @Test
    @DisplayName("A configured secret that holds '@' is withheld whole inside an authority")
    void secretWithAtSignInAnAuthority() {
        String head = random();
        String tail = random();
        String secret = head + "@" + tail;

        String safe = LogRedaction.of("jdbc:postgresql://u:" + secret + "@h/d", secret);

        assertThat(safe).doesNotContain(head).doesNotContain(tail).contains("@h/d");
    }

    @Test
    @DisplayName("A configured secret that holds '/' is withheld whole inside an authority")
    void secretWithSlashInAnAuthority() {
        String head = random();
        String tail = random();
        String secret = head + "/" + tail;

        String safe = LogRedaction.of("jdbc:postgresql://u:" + secret + "@h/d", secret);

        assertThat(safe).doesNotContain(head).doesNotContain(tail).contains("@h/d");
    }

    @Test
    @DisplayName("A very long secret is withheld")
    void veryLongSecret() {
        String secret = "k".repeat(200_000) + random();

        String safe = LogRedaction.of("before " + secret + " after", secret);

        assertThat(safe).isEqualTo("before " + W + " after");
    }

    @Test
    @DisplayName("An empty secret changes nothing and does not turn every position into a match")
    void emptySecret() {
        String message = "FATAL: could not connect to server";

        assertThat(LogRedaction.of(message, "")).isEqualTo(message);
        assertThat(LogRedaction.of(message, "", "")).isEqualTo(message);
    }

    @Test
    @DisplayName("A one-character secret is withheld wherever that character appears")
    void oneCharacterSecret() {
        String safe = LogRedaction.of("abcabc", "b");

        assertThat(safe).isEqualTo("a" + W + "ca" + W + "c");
    }

    @Test
    @DisplayName("A null secret is ignored and the others still apply")
    void nullSecret() {
        String secret = random();

        String safe = LogRedaction.of("x " + secret + " y", null, secret, null);

        assertThat(safe).isEqualTo("x " + W + " y");
    }

    @Test
    @DisplayName("No secrets at all, not even an array, is accepted")
    void noSecretsArray() {
        assertThatCode(() -> LogRedaction.of("message", (String[]) null)).doesNotThrowAnyException();
        assertThat(LogRedaction.of("message")).isEqualTo("message");
    }

    @Test
    @DisplayName("Several secrets are each withheld")
    void severalSecrets() {
        String one = random();
        String two = random();

        assertThat(LogRedaction.of(one + "," + two + "," + one, one, two)).isEqualTo(W + "," + W + "," + W);
    }

    @Test
    @DisplayName("The configured secret is withheld where no label names it")
    void secretWithoutALabel() {
        String secret = random();

        assertThat(LogRedaction.of("the pool said " + secret + " and gave up", secret))
                .isEqualTo("the pool said " + W + " and gave up");
    }

    @Test
    @DisplayName("An authentication failure that names a user and no credential is unchanged")
    void authenticationFailureUnchanged() {
        String message = "FATAL: password authentication failed for user \"x\"";

        assertThat(LogRedaction.of(message, random())).isEqualTo(message);
    }

    @Test
    @DisplayName("A message without credentials is unchanged, URLs without a password included")
    void plainMessageUnchanged() {
        String message = "No license manifest found: set EXERIS_LICENSE_MANIFEST_PATH (code LIC-001); "
                + "jdbc:postgresql://u@h:5432/d?ssl=true&sslmode=require";

        assertThat(LogRedaction.of(message, random())).isEqualTo(message);
    }

    @Test
    @DisplayName("No message, or a blank one, is reported as no message")
    void noMessage() {
        assertThat(LogRedaction.of(null)).isEqualTo("(no message)");
        assertThat(LogRedaction.of("")).isEqualTo("(no message)");
        assertThat(LogRedaction.of("  \t\n")).isEqualTo("(no message)");
        assertThat(LogRedaction.of(null, random())).isEqualTo("(no message)");
    }

    @Test
    @DisplayName("It never throws, whatever the message and the secrets")
    void neverThrows() {
        String alphabet = "@:/&=;'\"% \\$?#()passwordtokensecretpwdjdbc:postgresql://";
        Random random = new Random(RANDOM.nextLong());
        for (int round = 0; round < 3_000; round++) {
            StringBuilder message = new StringBuilder();
            for (int i = random.nextInt(60); i >= 0; i--) {
                message.append(alphabet.charAt(random.nextInt(alphabet.length())));
            }
            String secret = random.nextBoolean() ? null : message.substring(0, random.nextInt(message.length() + 1));
            String text = message.toString();

            assertThatCode(() -> LogRedaction.of(text, secret, "")).as(text).doesNotThrowAnyException();
        }
    }

    @Test
    @DisplayName("A megabyte of pathological input is handled in about a second, not exponentially")
    void linearTime() {
        LogRedaction.of("warm-up jdbc:postgresql://u:p@h/d?password=x&ssl=true", "p");
        List<String> inputs = List.of(
                "@:".repeat(500_000),
                "://" + ":".repeat(1_000_000),
                ("://u" + ":@".repeat(10)).repeat(40_000),
                "password" + " ".repeat(1_000_000),
                "password=" + " ".repeat(1_000_000) + "x",
                "password=".repeat(110_000),
                ("password:" + "a".repeat(20)).repeat(40_000),
                "://" + "a:".repeat(500_000),
                "ssl".repeat(330_000),
                "@".repeat(1_000_000));
        for (String input : inputs) {
            long start = System.nanoTime();
            String safe = LogRedaction.of(input, "zzzz");
            Duration took = Duration.ofNanos(System.nanoTime() - start);

            assertThat(safe).isNotNull();
            assertThat(took).as("a %d-character input starting %s", input.length(), input.substring(0, 12))
                    .isLessThan(Duration.ofSeconds(1));
        }
    }
}
