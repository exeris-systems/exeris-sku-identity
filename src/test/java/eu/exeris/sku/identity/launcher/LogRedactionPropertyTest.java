package eu.exeris.sku.identity.launcher;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Properties of {@link LogRedaction} over generated input. Generation is seeded: the seed is
 * {@value #DEFAULT_SEED} unless the {@code redaction.seed} system property names another, and every failure
 * message carries the seed that produced it.
 */
@DisplayName("LogRedaction properties")
class LogRedactionPropertyTest {

    private static final long DEFAULT_SEED = 20_261_111L;
    private static final long SEED = Long.getLong("redaction.seed", DEFAULT_SEED);
    private static final String W = LogRedaction.WITHHELD;
    private static final String UNREADABLE = "(message withheld)";

    /** Characters a secret is drawn from; none of them occurs in the placeholder. */
    private static final String SECRET_ALPHABET = "abcXYZ019&@/:=\"'\\$%+ éß漢~!*()#?;,";

    private static final List<String> LABELS = List.of("password", "PASSWD", "db_pwd", "passphrase", "client.secret",
            "X-Api-Key", "refresh_token", "credentials", "keyStorePassword", "Password");
    private static final List<String> SEPARATORS = List.of("=", ":", " = ", " : ", ": ");
    private static final List<String> QUOTES = List.of("", "'", "\"");
    private static final List<String> TAILS = List.of("", "&z=1", ";z=1", ",z", ")", " tail", "'", "\"");
    private static final List<String> AUTHORITY_HEADS = List.of("jdbc:postgresql://u:", "postgres://user:");
    private static final List<String> AUTHORITY_TAILS = List.of("@h/d", "@host:5432/db?x=1");
    private static final List<String> BARE_HEADS = List.of("x ", "", "word");
    private static final List<String> BARE_TAILS = List.of(" y", "", "word");

    /** Every fixed piece of text the generated messages are made of, joined by a placeholder. */
    private static final String SCAFFOLD = String.join(W, LABELS) + W + String.join(W, SEPARATORS) + W
            + String.join(W, QUOTES) + W + String.join(W, TAILS) + W + String.join(W, AUTHORITY_HEADS) + W
            + String.join(W, AUTHORITY_TAILS) + W + String.join(W, BARE_HEADS) + W + String.join(W, BARE_TAILS)
            + W + "&" + W + "?password=" + W + " " + W + "x?password=";

    private static String seedNote() {
        return "seed=" + SEED;
    }

    // ---- helpers ---------------------------------------------------------------------------------------

    private static String forms(String secret, Set<String> into) {
        String encoded = URLEncoder.encode(secret, StandardCharsets.UTF_8);
        String percent = encoded.replace("+", "%20");
        for (String form : new String[] {secret, encoded, percent, lowerEscapes(encoded), lowerEscapes(percent)}) {
            into.add(form);
        }
        return secret;
    }

    private static String lowerEscapes(String encoded) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < encoded.length(); i++) {
            char c = encoded.charAt(i);
            out.append(c);
            if (c == '%' && i + 2 < encoded.length()) {
                out.append(Character.toLowerCase(encoded.charAt(i + 1))).append(Character.toLowerCase(encoded.charAt(i + 2)));
                i += 2;
            }
        }
        return out.toString();
    }

    /** The plain and URL-encoded spellings of a secret. */
    private static Set<String> spellings(String... secrets) {
        Set<String> all = new LinkedHashSet<>();
        for (String secret : secrets) {
            forms(secret, all);
        }
        return all;
    }

    /** Whether text that is not a placeholder still holds the form; an occurrence cannot span a placeholder. */
    private static boolean survives(String output, String form) {
        for (String segment : output.split(java.util.regex.Pattern.quote(W), -1)) {
            if (segment.contains(form)) {
                return true;
            }
        }
        return false;
    }

    private static String randomSecret(Random random) {
        while (true) {
            int length = 3 + random.nextInt(8);
            StringBuilder secret = new StringBuilder();
            for (int i = 0; i < length; i++) {
                secret.append(SECRET_ALPHABET.charAt(random.nextInt(SECRET_ALPHABET.length())));
            }
            String value = secret.toString();
            boolean collides = false;
            for (String form : spellings(value)) {
                collides |= SCAFFOLD.contains(form);
            }
            if (!collides) {
                return value;
            }
        }
    }

    private static <T> T pick(Random random, List<T> from) {
        return from.get(random.nextInt(from.size()));
    }

    // ---- 17: idempotence and the security property with hostile secrets ------------------------------

    @Test
    @DisplayName("Idempotence: of(of(x, s), s) equals of(x, s) for secrets that are not drawn from the placeholder")
    void idempotence() {
        Random random = new Random(SEED);
        for (int round = 0; round < 3_000; round++) {
            String one = randomSecret(random);
            String two = randomSecret(random);
            String message = randomMessage(random, one, two);

            String once = LogRedaction.of(message, one, two);
            String twice = LogRedaction.of(once, one, two);

            assertThat(twice).as("%s round %d message %s", seedNote(), round, message).isEqualTo(once);
        }
    }

    private static String randomMessage(Random random, String... secrets) {
        List<String> pieces = new ArrayList<>();
        pieces.addAll(List.of("connect failed", "password=", "token: ", "://u:", "@h/d", "'", "\"", "&", ";", ",", ")",
                " ", "key = ", "x", "secret:", "\n", "jdbc:postgresql://", "pwd=", "%", "+", "abc"));
        pieces.addAll(List.of(secrets));
        StringBuilder message = new StringBuilder();
        for (int i = 1 + random.nextInt(14); i > 0; i--) {
            message.append(pick(random, pieces));
        }
        return message.toString();
    }

    /** Secrets built from the placeholder's own characters, and text that lets a placeholder and its neighbour spell one. */
    private static final List<String> HOSTILE = List.of("<withheld>x", "xx<", ">abc", "withheld", "wit", "<wit", "d>xy",
            "abc", "xyz<", "ld>a", "heldxyz", "a<b", ">>>", "<<<", "<withheld>", "held", "hel", "xyz", "abcd");

    @Test
    @DisplayName("Hostile secrets, drawn from the placeholder's characters: no secret survives outside a placeholder, in the first pass or the second")
    void hostileSecretsNeverSurvive() {
        Random random = new Random(SEED + 1);
        int nonIdempotent = 0;
        for (int round = 0; round < 5_000; round++) {
            List<String> chosen = new ArrayList<>();
            for (int i = 1 + random.nextInt(3); i > 0; i--) {
                chosen.add(pick(random, HOSTILE));
            }
            String[] secrets = chosen.toArray(String[]::new);
            StringBuilder message = new StringBuilder("x");
            for (int i = 2 + random.nextInt(8); i > 0; i--) {
                message.append(random.nextBoolean() ? pick(random, HOSTILE) : pick(random, List.of("abc", "xyz", " ", "=", "&")));
            }

            String once = LogRedaction.of(message.toString(), secrets);
            String twice = LogRedaction.of(once, secrets);
            if (!once.equals(twice)) {
                nonIdempotent++;
            }

            for (String secret : chosen) {
                if (W.contains(secret)) {
                    continue; // a part of the placeholder is covered by its own test
                }
                assertThat(survives(once, secret)).as("%s round %d: %s survives in %s of %s", seedNote(), round, secret, once, message).isFalse();
                assertThat(survives(twice, secret)).as("%s round %d: second pass: %s in %s", seedNote(), round, secret, twice).isFalse();
            }
        }
        System.out.println("[hostile-secrets] second pass differed from the first in " + nonIdempotent + " of 5000 rounds");
    }

    @Test
    @DisplayName("A secret that is a part of the placeholder text does not survive in a message that carries it")
    void secretThatIsAPartOfThePlaceholder() {
        for (String secret : List.of("held", "with", "hel", "<wit", "eld>")) {
            String safe = LogRedaction.of("the pool said " + secret + " and gave up", secret);

            assertThat(survives(safe, secret)).as("%s in %s", secret, safe).isFalse();
        }
    }

    // ---- 18: order independence -----------------------------------------------------------------------

    @Test
    @DisplayName("The result does not depend on the order of up to four secrets, including prefixes, suffixes, substrings and overlaps")
    void orderIndependence() {
        List<String> pool = List.of("abc", "abcd", "bcd", "xabc", "bcda", "cdab", "a b", "ab&", "&ab", "abcabc");
        Random random = new Random(SEED + 2);
        for (int round = 0; round < 400; round++) {
            List<String> chosen = new ArrayList<>(pool);
            java.util.Collections.shuffle(chosen, random);
            chosen = new ArrayList<>(chosen.subList(0, 2 + random.nextInt(3)));
            StringBuilder message = new StringBuilder("m");
            for (int i = 2 + random.nextInt(6); i > 0; i--) {
                String piece = pick(random, pool);
                // overlap with what precedes: repeat the tail of the message as the head of the piece
                int overlap = Math.min(message.length(), random.nextInt(4));
                message.append(overlap > 0 && random.nextBoolean() ? piece.substring(Math.min(overlap, piece.length() - 1)) : piece);
            }
            String text = message.toString();
            String expected = LogRedaction.of(text, chosen.toArray(String[]::new));
            for (List<String> permutation : permutations(chosen)) {
                assertThat(LogRedaction.of(text, permutation.toArray(String[]::new)))
                        .as("%s round %d order %s message %s", seedNote(), round, permutation, text)
                        .isEqualTo(expected);
            }
            for (String secret : chosen) {
                assertThat(survives(expected, secret)).as("%s %s in %s", seedNote(), secret, expected).isFalse();
            }
        }
    }

    private static List<List<String>> permutations(List<String> items) {
        if (items.size() <= 1) {
            return List.of(items);
        }
        List<List<String>> result = new ArrayList<>();
        for (int i = 0; i < items.size(); i++) {
            List<String> rest = new ArrayList<>(items);
            String head = rest.remove(i);
            for (List<String> tail : permutations(rest)) {
                List<String> permutation = new ArrayList<>();
                permutation.add(head);
                permutation.addAll(tail);
                result.add(permutation);
            }
        }
        return result;
    }

    // ---- 19: the security property under generation ---------------------------------------------------

    @Test
    @DisplayName("No secret of three or more characters survives, in plain or URL-encoded form, in any structural position")
    void noSecretSurvivesInAnyPosition() {
        Random random = new Random(SEED + 3);
        for (int round = 0; round < 250; round++) {
            String secret = randomSecret(random);
            String other = randomSecret(random);
            String longer = randomSecret(random) + secret + randomSecret(random);
            if (spellings(longer).stream().anyMatch(SCAFFOLD::contains)) {
                continue;
            }
            Set<String> forbidden = spellings(secret, other, longer);
            List<String> messages = new ArrayList<>();
            for (String form : spellings(secret)) {
                messages.add("x " + form + " y");
                messages.add("x?password=" + form + "&y");
                messages.add("jdbc:postgresql://u:" + form + "@h/d");
                messages.add(form + form);
                messages.add(form + " " + form);
            }
            for (int i = 0; i < 80; i++) {
                String form = pick(random, new ArrayList<>(spellings(secret)));
                messages.add(pick(random, LABELS) + pick(random, SEPARATORS) + pick(random, QUOTES) + form
                        + pick(random, QUOTES) + pick(random, TAILS));
            }
            messages.add(pick(random, BARE_HEADS) + secret + pick(random, BARE_TAILS));
            messages.add(secret + other);
            messages.add(other + secret);
            messages.add(secret + " " + other);
            messages.add(secret + "&" + other);
            messages.add("p=" + longer + "!");
            messages.add("password=" + longer + "&q");
            messages.add(secret + secret + secret);
            messages.add(pick(random, AUTHORITY_HEADS) + longer + pick(random, AUTHORITY_TAILS));
            messages.add(pick(random, AUTHORITY_HEADS) + secret + pick(random, AUTHORITY_TAILS));
            messages.add(pick(random, AUTHORITY_HEADS) + other + secret + pick(random, AUTHORITY_TAILS));

            for (String message : messages) {
                String safe = LogRedaction.of(message, secret, other, longer);

                for (String form : forbidden) {
                    assertThat(survives(safe, form)).as("%s round %d: %s survives in %s (from %s)", seedNote(), round,
                            form, safe, message).isFalse();
                }
            }
        }
    }

    // ---- 20: short secrets ----------------------------------------------------------------------------

    @Test
    @DisplayName("A one- or two-character secret is not replaced where it merely occurs, and is withheld as a labelled value and as an authority password")
    void shortSecrets() {
        for (String secret : List.of("=", "@", " ", "%", "a", "ab", "b", "\u00e9", "\u6f22\u6f22")) {
            String plain = "abab " + secret + " cd" + secret + secret + " end";
            assertThat(LogRedaction.of(plain, secret)).as("plain text with %s", secret).isEqualTo(plain);
        }
        for (String secret : List.of("b", "ab", "\u00e9", "\u6f22\u6f22", "x1")) {
            assertThat(LogRedaction.of("password=" + secret, secret)).as(secret).isEqualTo("password=" + W);
            assertThat(LogRedaction.of("x password: " + secret + "&y", secret)).as(secret).isEqualTo("x password: " + W + "&y");
            assertThat(LogRedaction.of("jdbc:postgresql://u:" + secret + "@h/d", secret)).as(secret)
                    .isEqualTo("jdbc:postgresql://u:" + W + "@h/d");
        }
    }

    @Test
    @DisplayName("A short secret next to a long one: the long one is withheld and the short one's characters elsewhere stay")
    void shortAndLongSecretsTogether() {
        String safe = LogRedaction.of("b abc b hunter2 b", "b", "hunter2");

        assertThat(safe).isEqualTo("b abc b " + W + " b");
    }

    // ---- 21: labels -----------------------------------------------------------------------------------

    @Test
    @DisplayName("A sensitive word inside a name, with any prefix, suffix or case, makes its value withheld")
    void sensitiveWordsInNames() {
        for (String name : List.of("db_password", "X-Api-Key", "sslkey", "keyStorePassword", "client.secret",
                "refresh_token", "PGPASSWORD", "SECRET", "x-auth-token", "Credentials", "app.credential.id",
                "monkey", "PASSPHRASE", "my_pwd", "ApiKey", "tokenValue", "a-b_c.d-token-e")) {
            assertThat(LogRedaction.of(name + "=value&n=1")).as(name).isEqualTo(name + "=" + W + "&n=1");
            assertThat(LogRedaction.of("{" + name + ": value, n: 1}")).as(name).isEqualTo("{" + name + ": " + W + ", n: 1}");
            assertThat(LogRedaction.of(name + " = 'a b' x")).as(name).isEqualTo(name + " = '" + W + "' x");
        }
    }

    @Test
    @DisplayName("Names that merely resemble a sensitive word are left as they are: auth, author, bypass, keepalive, pass")
    void resemblingNamesAreNotWithheld() {
        for (String name : List.of("auth", "author", "bypass", "keepalive", "pass", "authorization", "authority",
                "passthrough", "session", "user", "sid", "cookie")) {
            assertThat(LogRedaction.of(name + "=x")).as(name).isEqualTo(name + "=x");
            assertThat(LogRedaction.of(name + ": x")).as(name).isEqualTo(name + ": x");
        }
    }

    @Test
    @DisplayName("Ordinary prose, YAML, properties, key/value connection strings and Properties.toString() keep everything but the value")
    void commonShapes() {
        assertThat(LogRedaction.of("Error: key: value")).isEqualTo("Error: key: " + W);
        assertThat(LogRedaction.of("db:\n  password: hunter2\n  user: u\n")).isEqualTo("db:\n  password: " + W + "\n  user: u\n");
        assertThat(LogRedaction.of("db.password=hunter2\ndb.user=u\n")).isEqualTo("db.password=" + W + "\ndb.user=u\n");
        assertThat(LogRedaction.of("host=h user=u password=p dbname=d")).isEqualTo("host=h user=u password=" + W + " dbname=d");
        assertThat(LogRedaction.of("{password=p, user=u}")).isEqualTo("{password=" + W + ", user=u}");
        assertThat(LogRedaction.of("X-Auth-Token: abc.def\r\nHost: h")).isEqualTo("X-Auth-Token: " + W + "\r\nHost: h");
        assertThat(LogRedaction.of("FATAL: password authentication failed for user \"x\""))
                .isEqualTo("FATAL: password authentication failed for user \"x\"");
    }

    @Test
    @DisplayName("A stack-trace line is cut only after a class name that holds a sensitive word and a colon")
    void stackTraceLines() {
        assertThat(LogRedaction.of("at com.example.Loader.load(Loader.java:42)")).isEqualTo("at com.example.Loader.load(Loader.java:42)");
        assertThat(LogRedaction.of("at com.example.Loader.getPassword(Loader.java:42)"))
                .isEqualTo("at com.example.Loader.getPassword(Loader.java:42)");
        // over-withholding by the rule: the file name holds "key" and is followed by a colon
        assertThat(LogRedaction.of("at x.KeyStoreLoader.load(KeyStoreLoader.java:42)"))
                .isEqualTo("at x.KeyStoreLoader.load(KeyStoreLoader.java:" + W + ")");
    }

    @Test
    @DisplayName("Residual risk, pinned: a JSON body, an Authorization header, a cookie and a space-separated value are not found by the label rule")
    void shapesTheLabelRuleDoesNotCover() {
        assertThat(LogRedaction.of("{\"password\":\"hunter2\",\"user\":\"u\"}")).isEqualTo("{\"password\":\"hunter2\",\"user\":\"u\"}");
        assertThat(LogRedaction.of("Authorization: Bearer abc.def.ghi")).isEqualTo("Authorization: Bearer abc.def.ghi");
        assertThat(LogRedaction.of("Authorization: Basic dXNlcjpwYXNz")).isEqualTo("Authorization: Basic dXNlcjpwYXNz");
        assertThat(LogRedaction.of("Cookie: sid=abc123")).isEqualTo("Cookie: sid=abc123");
        assertThat(LogRedaction.of("--password hunter2")).isEqualTo("--password hunter2");
    }

    @Test
    @DisplayName("A configured secret is withheld in the shapes the label rule does not cover")
    void configuredSecretCoversTheOtherShapes() {
        String secret = "hunter2-secret";

        assertThat(LogRedaction.of("{\"password\":\"" + secret + "\"}", secret)).isEqualTo("{\"password\":\"" + W + "\"}");
        assertThat(LogRedaction.of("Authorization: Bearer " + secret, secret)).isEqualTo("Authorization: Bearer " + W);
        assertThat(LogRedaction.of("--password " + secret, secret)).isEqualTo("--password " + W);
    }

    // ---- 22: robustness -------------------------------------------------------------------------------

    @Test
    @DisplayName("Null and empty secrets, a null secret array, a null or blank message")
    void degenerateArguments() {
        assertThat(LogRedaction.of("m", (String[]) null)).isEqualTo("m");
        assertThat(LogRedaction.of("m", null, "", null, "")).isEqualTo("m");
        assertThat(LogRedaction.of(null, (String[]) null)).isEqualTo("(no message)");
        assertThat(LogRedaction.of(" \n\t ", "abc")).isEqualTo("(no message)");
        assertThat(LogRedaction.of("", (String[]) null)).isEqualTo("(no message)");
    }

    @Test
    @DisplayName("Malformed UTF-16 in the message and in a secret never throws and never takes the unreadable path")
    void malformedUtf16() {
        String highAlone = "\uD800";
        String lowAlone = "\uDC00";
        List<String> messages = List.of(highAlone, lowAlone, lowAlone + highAlone, "password=" + highAlone + "x",
                "://u:" + lowAlone + "@h", "x" + highAlone + highAlone + "abc" + lowAlone, "￿￾\u0000abc");
        List<String[]> secretSets = List.of(new String[] {highAlone + "ab"}, new String[] {"ab" + lowAlone},
                new String[] {lowAlone + highAlone + "z"}, new String[] {"\u0000\u0000\u0000"},
                new String[] {highAlone, lowAlone, "abc"});
        for (String message : messages) {
            for (String[] secrets : secretSets) {
                assertThatCode(() -> assertThat(LogRedaction.of(message, secrets)).isNotNull().isNotEqualTo(UNREADABLE))
                        .as("%s / %s", message, List.of(secrets)).doesNotThrowAnyException();
            }
        }
        assertThat(LogRedaction.of("p " + highAlone + "ab q", highAlone + "ab")).isEqualTo("p " + W + " q");
    }

    @Test
    @DisplayName("Random strings over a broad alphabet, surrogates included, never throw and never reach the unreadable result")
    void fuzzNeverReachesTheUnreadablePath() {
        String alphabet = "ab%+@:/=&'\"\\ \n\tpasswordkeytoken𐀀😀\u0000￿<>withheld;,()";
        Random random = new Random(SEED + 4);
        for (int round = 0; round < 20_000; round++) {
            StringBuilder message = new StringBuilder();
            for (int i = random.nextInt(80); i >= 0; i--) {
                message.append(alphabet.charAt(random.nextInt(alphabet.length())));
            }
            String[] secrets = new String[random.nextInt(4)];
            for (int i = 0; i < secrets.length; i++) {
                int from = random.nextInt(message.length());
                secrets[i] = random.nextInt(5) == 0 ? null : message.substring(from, Math.min(message.length(), from + random.nextInt(9)));
            }
            String text = message.toString();

            String safe = LogRedaction.of(text, secrets);

            assertThat(safe).as("%s round %d of %s with %s", seedNote(), round, text, java.util.Arrays.toString(secrets))
                    .isNotNull().isNotEqualTo(UNREADABLE);
        }
    }

    @Test
    @DisplayName("A megabyte of name characters, of '://a:', of quotes and of '%' is handled within a second each, with and without a secret")
    void megabyteInputs() {
        LogRedaction.of("warm-up jdbc:postgresql://u:p@h/d?password=x&ssl=true 'q' %41", "%%%", "zzzz");
        Map<String, String> inputs = Map.of(
                "name characters", "a".repeat(1 << 20),
                "name characters with a sensitive word", "password".repeat(1 << 17),
                "authority openings", "://a:".repeat(1 << 18),
                "single quotes", "'".repeat(1 << 20),
                "labelled quotes", "password='".repeat(1 << 17),
                "double quotes after a label", "key=\"".repeat(1 << 18),
                "percent signs", "%".repeat(1 << 20),
                "escapes", "%2F%40".repeat(1 << 18));
        for (Map.Entry<String, String> input : inputs.entrySet()) {
            for (String[] secrets : List.of(new String[0], new String[] {"zzzz", "%%%", "aaa", "%2F%40", "password='"})) {
                long start = System.nanoTime();
                String safe = LogRedaction.of(input.getValue(), secrets);
                Duration took = Duration.ofNanos(System.nanoTime() - start);

                assertThat(safe).isNotNull().isNotEqualTo(UNREADABLE);
                assertThat(took).as("%s with %d secrets", input.getKey(), secrets.length).isLessThan(Duration.ofSeconds(1));
            }
        }
    }

    // ---- 23: text outside a withheld value is unchanged -----------------------------------------------

    /**
     * Whether the input is the output with something inserted where each placeholder stands: the segments
     * between placeholders appear in the input in order, the first as a prefix and the last as a suffix.
     */
    private static boolean onlyWithheldSpansWereCut(String input, String output) {
        String[] segments = output.split(java.util.regex.Pattern.quote(W), -1);
        if (segments.length == 1) {
            return input.equals(output);
        }
        if (!input.startsWith(segments[0])) {
            return false;
        }
        int at = segments[0].length();
        for (int i = 1; i < segments.length - 1; i++) {
            int found = input.indexOf(segments[i], at);
            if (found < 0) {
                return false;
            }
            at = found + segments[i].length();
        }
        String last = segments[segments.length - 1];
        return input.length() - last.length() >= at && input.endsWith(last);
    }

    @Test
    @DisplayName("Everything outside the withheld spans is the input byte for byte")
    void textOutsideWithheldValuesIsUnchanged() {
        Random random = new Random(SEED + 5);
        for (int round = 0; round < 6_000; round++) {
            String one = randomSecret(random);
            String two = randomSecret(random);
            String message = randomMessage(random, one, two, "éß", "line1\r\nline2");
            if (message.isBlank()) {
                continue;
            }

            String safe = LogRedaction.of(message, one, two);

            assertThat(onlyWithheldSpansWereCut(message, safe)).as("%s round %d: input %s output %s", seedNote(), round,
                    message, safe).isTrue();
        }
    }
}
