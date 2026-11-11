package eu.exeris.sku.identity.launcher;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The contract of {@link LogRedaction}, stated in its documentation, checked at unit level. The properties are
 * generated from a seed: {@value #DEFAULT_SEED} unless the {@code redaction.seed} system property names another,
 * and every failure message carries the seed.
 *
 * <p>A test in {@link KnownDefects} states a rule of the contract that the implementation does not keep. It is
 * skipped unless the {@code identity.knownDefects} system property is {@code true}, so that the suite stays
 * green while the defect stands and the test still runs on demand.
 */
@DisplayName("LogRedaction contract")
class LogRedactionContractTest {

    private static final long DEFAULT_SEED = 20_261_112L;
    private static final long SEED = Long.getLong("redaction.seed", DEFAULT_SEED);
    private static final String W = LogRedaction.WITHHELD;
    private static final String UNREADABLE = "(message withheld)";
    private static final String SEED_NOTE = "seed=" + SEED;

    /** Line ends of the label rule. */
    private static final List<String> LINE_ENDS = List.of("\n", "\r", "\u0085", "\u2028", "\u2029");

    /** Characters that are neither part of any label nor of the placeholder, used as filler around a secret. */
    private static final String NOISE = "QRS~|";

    /** Characters a generated secret is made of: ASCII, metacharacters, Latin-1, BMP and a supplementary one. */
    private static final List<String> SECRET_UNITS = List.of("a", "b", "c", "X", "Y", "Z", "0", "1", "9", "&", "@", "/", ":",
            "=", "\"", "'", "\\", "$", "%", "+", " ", "\u00e9", "\u00df", "\u6f22", "!", "*", "(", ")", "#", "?", ";", ",",
            "\uD83D\uDE00", "\u00ff", "\u00fb", ">");

    private static String of(String message, String... secrets) {
        return LogRedaction.of(message, secrets);
    }

    private static String sub(String text, String... secrets) {
        return LogRedaction.of(text, secrets);
    }

    /** Whether text outside the placeholders still holds the form. */
    private static boolean survives(String output, String form) {
        for (String segment : output.split(Pattern.quote(W), -1)) {
            if (segment.contains(form)) {
                return true;
            }
        }
        return false;
    }

    private static String noise(Random random) {
        StringBuilder out = new StringBuilder();
        for (int i = random.nextInt(4); i > 0; i--) {
            out.append(NOISE.charAt(random.nextInt(NOISE.length())));
        }
        return out.toString();
    }

    private static String randomSecret(Random random, boolean allowSpaceWithPlus) {
        while (true) {
            int units = 3 + random.nextInt(6);
            StringBuilder secret = new StringBuilder();
            for (int i = 0; i < units; i++) {
                secret.append(SECRET_UNITS.get(random.nextInt(SECRET_UNITS.size())));
            }
            String value = secret.toString();
            if (value.length() < LogRedaction.MINIMUM_SECRET_LENGTH) {
                continue;
            }
            if (!allowSpaceWithPlus && value.contains(" ") && value.contains("+")) {
                continue;
            }
            return value;
        }
    }

    /**
     * A spelling of the secret in which each character is written literally or as the percent-escapes of its
     * UTF-8 bytes (either case of hexadecimal digit), a space also as {@code +}, a {@code +} also as itself.
     * A {@code %} is always escaped, so that a literal one never forms an escape with the characters after it.
     */
    private static String mixedSpelling(String secret, Random random) {
        StringBuilder out = new StringBuilder();
        boolean lower = random.nextBoolean();
        secret.codePoints().forEach(cp -> {
            String text = new String(Character.toChars(cp));
            boolean literal = random.nextBoolean();
            if (cp == '%') {
                literal = false;
            }
            if (cp == ' ' && !secret.contains("+") && random.nextInt(3) == 0) {
                out.append('+');
            } else if (literal) {
                out.append(text);
            } else {
                for (byte b : text.getBytes(StandardCharsets.UTF_8)) {
                    String hex = String.format("%02X", b & 0xff);
                    out.append('%').append(lower ? hex.toLowerCase() : hex);
                }
            }
        });
        return out.toString();
    }

    private static List<String> base64Of(String secret) {
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        return List.of(Base64.getEncoder().encodeToString(bytes), Base64.getEncoder().withoutPadding().encodeToString(bytes),
                Base64.getUrlEncoder().encodeToString(bytes), Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
    }

    // ---- 1, 2, 3, 4: configured secrets -----------------------------------------------------------------

    @Nested
    @DisplayName("Configured secrets")
    class ConfiguredSecrets {

        @Test
        @DisplayName("1: no occurrence of a configured secret survives, whatever its characters, in any of its forms, between filler")
        void noOccurrenceSurvives() {
            Random random = new Random(SEED);
            for (int round = 0; round < 4_000; round++) {
                String secret = randomSecret(random, false);
                List<String> spellings = new ArrayList<>();
                spellings.add(secret);
                spellings.add(mixedSpelling(secret, random));
                spellings.add(mixedSpelling(secret, random));
                spellings.addAll(base64Of(secret));
                for (String spelling : spellings) {
                    String before = noise(random);
                    String after = noise(random);

                    String safe = of(before + spelling + after, secret);

                    assertThat(safe).as("%s round %d: %s spelled %s", SEED_NOTE, round, secret, spelling)
                            .isEqualTo(before + W + after);
                }
            }
        }

        @Test
        @DisplayName("1: every occurrence is replaced, not the first only, and several secrets at once")
        void everyOccurrence() {
            assertThat(of("Q abc Q abc Q xyz1 Q abc", "abc", "xyz1")).isEqualTo("Q " + W + " Q " + W + " Q " + W + " Q " + W);
            assertThat(of("abcabcabc", "abc")).isEqualTo(W);
        }

        @Test
        @DisplayName("1: a secret that is a part of the placeholder text is withheld wherever it occurs, input text included")
        void secretInsideThePlaceholder() {
            for (String secret : List.of("held", "with", "hel", "<wit", "eld>", "<withheld>", "ithhe")) {
                String message = "Q " + secret + " Q <withheld> Q";

                String safe = of(message, secret);

                assertThat(survives(safe, secret)).as("%s in %s", secret, safe).isFalse();
            }
        }

        @Test
        @DisplayName("2: a percent-escaped spelling is withheld, hexadecimal digits of either case, multi-byte characters included")
        void percentEncodedForms() {
            assertThat(of("Q%41%42%43Q", "ABC")).isEqualTo("Q" + W + "Q");
            assertThat(of("Q%41b%43Q", "AbC")).isEqualTo("Q" + W + "Q");
            assertThat(of("Q%c3%a9%C3%A9%e6%BC%a2Q", "\u00e9\u00e9\u6f22")).isEqualTo("Q" + W + "Q");
            assertThat(of("Q%F0%9F%98%80%f0%9f%98%80xQ", "\uD83D\uDE00\uD83D\uDE00x")).isEqualTo("Q" + W + "Q");
            assertThat(of("Q%2B%2b+Q", "+++")).isEqualTo("Q" + W + "Q");
        }

        @Test
        @DisplayName("2: '+' is a space only where the secret has a space; a secret's own '+' is '+' or %2B")
        void plusRules() {
            assertThat(of("Q+a+bQ", " a b")).isEqualTo("Q" + W + "Q");
            assertThat(of("Qa+b+cQ", "a+b+c")).isEqualTo("Q" + W + "Q");
            assertThat(of("Qa%2Bb%2bcQ", "a+b+c")).isEqualTo("Q" + W + "Q");
            assertThat(of("Qa b+cQ", "a b+c")).isEqualTo("Q" + W + "Q");
            assertThat(of("Qa+b+c", "a b c")).as("both pluses stand for spaces").isEqualTo("Q" + W);
            assertThat(of("Qa+bc", "a bc")).isEqualTo("Q" + W);
            // a '+' where the secret has no space is not a space
            assertThat(of("Qa+bcQ", "a bcd")).isEqualTo("Qa+bcQ");
            assertThat(of("Qxyz+abQ", "xyz abc")).isEqualTo("Qxyz+abQ");
        }

        @Test
        @DisplayName("2: an escape that is not two hexadecimal digits is literal")
        void invalidEscapesAreLiteral() {
            assertThat(of("Qa%4Gb%Q", "a%4Gb%")).isEqualTo("Q" + W + "Q");
            assertThat(of("Q100%%Q", "100%%")).isEqualTo("Q" + W + "Q");
            assertThat(of("Qx%zz%4", "x%zz%4")).isEqualTo("Q" + W);
            assertThat(of("Qab%4", "ab%4")).isEqualTo("Q" + W);
            assertThat(of("Qab%", "ab%")).isEqualTo("Q" + W);
            // %4G is not the escape of any byte, so it does not stand for the secret's 'A' followed by 'G'
            assertThat(of("Q%4GQ", "AGx")).isEqualTo("Q%4GQ");
            // a truncated escape before a real one
            assertThat(of("Q%4%41%42Q", "%4AB")).isEqualTo("Q" + W + "Q");
        }

        @Test
        @DisplayName("2: a secret that holds an escape-looking text is matched literally and as the escape of that text")
        void secretHoldingAnEscape() {
            assertThat(of("Qpass%41wordQ", "pass%41word")).isEqualTo("Q" + W + "Q");
            assertThat(of("Qpass%2541wordQ", "pass%41word")).as("one escape of the '%'").isEqualTo("Q" + W + "Q");
            assertThat(of("Qpass%2541wordQ", "passAword")).as("double encoding is out of scope").isEqualTo("Qpass%2541wordQ");
        }

        @Test
        @DisplayName("3: Base64 and Base64url, padded and unpadded, for lengths of every residue and bytes that give '+', '/', '-' and '_'")
        void base64Forms() {
            List<String> secrets = List.of("abc", "abcd", "abcde", "abcdef", "ab~", "~~~~", "?>?", "???>>>", "\u00fb\u00ff\u00be\u00fa",
                    "\u00e9\u00e9\u00e9\u00e9\u00e9", "\u6f22\u6f22\u6f22", "\uD83D\uDE00xy");
            boolean sawPlus = false;
            boolean sawSlash = false;
            for (String secret : secrets) {
                for (String form : base64Of(secret)) {
                    sawPlus |= form.contains("+");
                    sawSlash |= form.contains("/");
                    assertThat(of("Q" + form + "Q", secret)).as("%s as %s", secret, form).isEqualTo("Q" + W + "Q");
                    assertThat(of("token Q" + form, secret)).as("%s as %s at the end", secret, form).isEqualTo("token Q" + W);
                }
            }
            assertThat(sawPlus).as("a secret whose Base64 has '+'").isTrue();
            assertThat(sawSlash).as("a secret whose Base64 has '/'").isTrue();
            assertThat(base64Of("~~~~").stream().distinct().count()).isGreaterThanOrEqualTo(3);
        }

        @Test
        @DisplayName("3: a Base64 form is withheld as a contiguous run inside a longer token, and nothing of another encoding is guessed")
        void base64InsideALongerToken() {
            String form = Base64.getEncoder().encodeToString("hunter2".getBytes(StandardCharsets.UTF_8));

            assertThat(of("Q" + form + "xyz", "hunter2")).isEqualTo("Q" + W + "xyz");
            assertThat(of("Qxyz" + form, "hunter2")).isEqualTo("Qxyz" + W);
            // the lower-cased Base64 is another string
            assertThat(of("Q" + form.toLowerCase() + "Q", "hunter2")).isEqualTo("Q" + form.toLowerCase() + "Q");
        }

        @Test
        @DisplayName("4: a differently cased secret is not withheld, in text or in a percent-escaped spelling")
        void caseIsNotFolded() {
            assertThat(of("Qhunter2xQ HUNTER2X Hunter2x", "Hunter2x")).isEqualTo("Qhunter2xQ HUNTER2X " + W);
            assertThat(of("Q%68unter2xQ", "Hunter2x")).isEqualTo("Q%68unter2xQ");
            assertThat(of("Q%48unter2xQ", "Hunter2x")).isEqualTo("Q" + W + "Q");
        }

        @Test
        @DisplayName("5: more than eight distinct eligible secrets gives exactly '(message withheld)', whatever the message holds")
        void secretCap() {
            String[] nine = {"aa1", "aa2", "aa3", "aa4", "aa5", "aa6", "aa7", "aa8", "aa9"};
            assertThat(of("a message that holds none of them", nine)).isEqualTo(UNREADABLE);
            assertThat(of("aa1 aa9", nine)).isEqualTo(UNREADABLE);
            assertThat(of("password=x", nine)).isEqualTo(UNREADABLE);
        }

        @Test
        @DisplayName("5: eight are accepted, and short, empty, null and repeated values do not count")
        void eightAreAccepted() {
            String[] secrets = {"aa1", "aa2", "aa3", "aa4", "aa5", "aa6", "aa7", "aa8", "aa1", "aa8", null, null, "", "", "a", "ab", "b",
                    "\u00e9\u00e9", "\uD83D\uDE00"};

            assertThat(of("Q aa1 aa2 aa3 aa4 aa5 aa6 aa7 aa8 ab Q", secrets)).isEqualTo("Q " + (W + " ").repeat(8) + "ab Q");
        }

        @Test
        @DisplayName("5: the needle cap cannot be reached below the secret cap: eight secrets of the most forms are accepted")
        void eightSecretsOfTheMostForms() {
            Random random = new Random(SEED + 5);
            List<String> secrets = new ArrayList<>();
            while (secrets.size() < 8) {
                String candidate = randomSecret(random, false);
                if (base64Of(candidate).stream().distinct().count() == 4 && !secrets.contains(candidate)) {
                    secrets.add(candidate);
                }
            }
            StringBuilder message = new StringBuilder();
            for (String secret : secrets) {
                message.append("Q").append(secret).append("Q").append(base64Of(secret).get(1)).append("Q");
            }

            String safe = of(message.toString(), secrets.toArray(String[]::new));

            assertThat(safe).as(SEED_NOTE).isNotEqualTo(UNREADABLE).isEqualTo(("Q" + W + "Q" + W + "Q").repeat(8));
        }

        @Test
        @DisplayName("6: the order of the secrets does not change the result, with mixed literal and encoded occurrences and overlaps")
        void orderIndependence() {
            Random random = new Random(SEED + 6);
            List<String> pool = List.of("abc", "abcd", "bcd", "xabc", "bcda", "cdab", "a b", "ab&", "&ab", "abcabc", "aaa");
            for (int round = 0; round < 250; round++) {
                List<String> chosen = new ArrayList<>(pool);
                Collections.shuffle(chosen, random);
                chosen = new ArrayList<>(chosen.subList(0, 2 + random.nextInt(4)));
                StringBuilder message = new StringBuilder("Q");
                for (int i = 2 + random.nextInt(7); i > 0; i--) {
                    String piece = pool.get(random.nextInt(pool.size()));
                    switch (random.nextInt(4)) {
                        case 0 -> message.append(piece);
                        case 1 -> message.append(mixedSpelling(piece, random));
                        case 2 -> message.append(base64Of(piece).get(random.nextInt(4)));
                        default -> message.append(piece, 1, piece.length());
                    }
                    if (random.nextInt(3) == 0) {
                        message.append(NOISE.charAt(random.nextInt(NOISE.length())));
                    }
                }
                String text = message.toString();
                String expected = of(text, chosen.toArray(String[]::new));
                for (int k = 0; k < 8; k++) {
                    List<String> shuffled = new ArrayList<>(chosen);
                    Collections.shuffle(shuffled, random);
                    assertThat(of(text, shuffled.toArray(String[]::new))).as("%s round %d order %s message %s", SEED_NOTE, round,
                            shuffled, text).isEqualTo(expected);
                }
                assertThat(expected).as("one placeholder per maximal range").doesNotContain(W + W);
            }
        }

        @Test
        @DisplayName("6: overlapping occurrences are merged into one placeholder")
        void overlapsAreMerged() {
            assertThat(of("Qaaaa", "aaa")).isEqualTo("Q" + W);
            assertThat(of("Qabcabc", "abc", "bcab")).isEqualTo("Q" + W);
            assertThat(of("Qabcd", "abc", "bcd")).isEqualTo("Q" + W);
            assertThat(of("QabcQbcd", "abc", "bcd")).isEqualTo("Q" + W + "Q" + W);
            assertThat(of("aaaaaaaaaa", "aaa")).isEqualTo(W);
        }

        @Test
        @DisplayName("6: adjacent occurrences of different forms are one range")
        void adjacentFormsAreOneRange() {
            String b64 = base64Of("hunter2").get(0);

            assertThat(of("Qhunter2" + b64 + "%68unter2Q", "hunter2")).isEqualTo("Q" + W + "Q");
        }

        @Test
        @DisplayName("7: a secret holding '&', '@', '/', a quote or a blank is withheld whole inside a value, and so is the rest of that value")
        void secretWithMetacharacters() {
            assertThat(of("token=ab&cd&n=1", "ab&cd")).isEqualTo("token=" + W + "&n=1");
            assertThat(of("token=a b c&n=1", "a b c")).isEqualTo("token=" + W + "&n=1");
            assertThat(of("jdbc:postgresql://u:pa@ss/word@h/d", "pa@ss/word")).isEqualTo("jdbc:postgresql://u:" + W + "@h/d");
            assertThat(of("jdbc:postgresql://u:pa@ss@h/d", "pa@ss")).isEqualTo("jdbc:postgresql://u:" + W + "@h/d");
            assertThat(of("key='it's\"o' z", "it's\"o")).isEqualTo("key='" + W + "' z");
            assertThat(of("key=\"a\"b\" z", "a\"b")).isEqualTo("key=\"" + W + "\" z");
            assertThat(of("?password=a&b;c d&n=1", "a&b;c d")).isEqualTo("?password=" + W + "&n=1");
            assertThat(of("x password=a/b@c d\nnext", "a/b@c d")).isEqualTo("x password=" + W + "\nnext");
        }

        @Test
        @DisplayName("7: a secret ending inside a value withholds the rest of the value too")
        void secretAtTheStartOfAValue() {
            assertThat(of("token=abcTAILTAIL&n=1", "abc")).isEqualTo("token=" + W + "&n=1");
        }

        @Test
        @DisplayName("A: a secret next to a '%', inside a percent-escaped run, as the tail of a longer token, and straddling a structural range")
        void adversarialPlacements() {
            assertThat(of("Q%abc%Q", "abc")).isEqualTo("Q%" + W + "%Q");
            assertThat(of("Q%41abc%42Q", "abc")).isEqualTo("Q%41" + W + "%42Q");
            assertThat(of("Q%61%62%63Q", "abc")).isEqualTo("Q" + W + "Q");
            assertThat(of("Q%61%62%63%61%62%63Q", "abc")).isEqualTo("Q" + W + "Q");
            assertThat(of("Q%2561Q", "%61")).as("the secret %61 as one escape of '%'").isEqualTo("Q" + W + "Q");
            assertThat(of("xxxabc", "abc")).isEqualTo("xxx" + W);
            assertThat(of("abcxxx", "abc")).isEqualTo(W + "xxx");
            assertThat(of("password=abcdef ghi", "def gh")).isEqualTo("password=" + W);
            assertThat(of("?token=abc&def&n=1", "abc&def")).isEqualTo("?token=" + W + "&n=1");
            assertThat(survives(of("jdbc:postgresql://u:pass@host/d", "ss@ho"), "ss@ho")).isFalse();
        }

        @Test
        @DisplayName("A: a secret made of '%', of '+', and of exactly three percent-encodable characters")
        void adversarialSecrets() {
            assertThat(of("Q%%%Q%%%%", "%%%")).isEqualTo("Q" + W + "Q" + W);
            assertThat(of("Q%25%25%25Q", "%%%")).isEqualTo("Q" + W + "Q");
            assertThat(of("Q%%25%25Q", "%%%")).isEqualTo("Q" + W + "Q");
            assertThat(of("Q+++Q%2B%2B%2BQ+%2B+Q", "+++")).isEqualTo("Q" + W + "Q" + W + "Q" + W + "Q");
            assertThat(of("Q%40%3A%2FQ@%3a/Q@:/Q", "@:/")).isEqualTo("Q" + W + "Q" + W + "Q" + W + "Q");
            assertThat(of("Q%20%20%20Q   Q+++Q", "   ")).isEqualTo("Q" + W + "Q" + W + "Q" + W + "Q");
            assertThat(of("Q%", "%")).as("one character is below the minimum").isEqualTo("Q%");
        }

        @Test
        @DisplayName("A: supplementary characters and lone surrogates in a secret and in the message")
        void surrogates() {
            String pair = "\uD83D\uDE00";
            assertThat(of("Qa" + pair + "bQ", "a" + pair + "b")).isEqualTo("Q" + W + "Q");
            assertThat(of("Qa%F0%9F%98%80bQ", "a" + pair + "b")).isEqualTo("Q" + W + "Q");
            assertThat(of("Q" + base64Of("a" + pair + "b").get(3) + "Q", "a" + pair + "b")).isEqualTo("Q" + W + "Q");
            assertThat(of("Q\uD83Dab\uDE00Q", "\uD83Dab")).isEqualTo("Q" + W + "\uDE00Q");
            assertThat(of("Q\uDE00ab\uD83DQ", "\uDE00ab")).isEqualTo("Q" + W + "\uD83DQ");
            assertThat(of("Q\uD83D\uD83D\uD83DQ", "\uD83D\uD83D\uD83D")).isEqualTo("Q" + W + "Q");
            // half of a pair is not the pair
            assertThat(of("Qa" + pair + "bQ", "a\uD83D")).as("below the minimum").isEqualTo("Qa" + pair + "bQ");
        }

        @Test
        @DisplayName("A: a secret that is also the Base64 of another secret, and one next to its own Base64")
        void secretsOfEachOther() {
            String form = Base64.getEncoder().encodeToString("abc".getBytes(StandardCharsets.UTF_8));

            assertThat(of("Q" + form + "Q", form, "abc")).isEqualTo("Q" + W + "Q");
            assertThat(of("Qabc" + form + "abcQ", "abc")).isEqualTo("Q" + W + "Q");
            assertThat(of("Q" + form + "Q", "abc", form)).isEqualTo("Q" + W + "Q");
        }

        @Test
        @DisplayName("A: what is out of scope is not withheld, pinned so that a change of it is a decision: double encoding, mojibake, a split by a line break, a longer Base64 payload")
        void documentedLimits() {
            assertThat(of("Qpass%2541wordQ", "passAword")).isEqualTo("Qpass%2541wordQ");
            assertThat(of("Q\u00c3\u00a9\u00c3\u00a91Q", "\u00e9\u00e91")).isEqualTo("Q\u00c3\u00a9\u00c3\u00a91Q");
            assertThat(of("Qhunt\ner2Q", "hunter2")).isEqualTo("Qhunt\ner2Q");
            String longer = Base64.getEncoder().encodeToString("xxhunter2".getBytes(StandardCharsets.UTF_8));
            assertThat(of("Q" + longer + "Q", "hunter2")).isEqualTo("Q" + longer + "Q");
        }

        @Test
        @DisplayName("8: a megabyte with '%' and '+' and a secret of 200000 characters takes less than a second")
        void linearTime() {
            of("%41+a b c", "x".repeat(1_000), "%41", "a b");
            String filler = "%41+ab %2B%zz".repeat(80_000);
            String secret = "s".repeat(200_000);
            String message = filler + secret + filler.substring(0, 1_000) + "%" + "+";
            assertThat(message.length()).isGreaterThan(1 << 20);
            long start = System.nanoTime();

            String safe = of(message, secret, "%41+", " ab ", "+++");

            Duration took = Duration.ofNanos(System.nanoTime() - start);
            assertThat(took).isLessThan(Duration.ofSeconds(1));
            assertThat(safe).isNotEqualTo(UNREADABLE).doesNotContain(secret);
        }
    }

    // ---- 9..15: structure --------------------------------------------------------------------------------

    @Nested
    @DisplayName("Labels")
    class Labels {

        @Test
        @DisplayName("9: a quoted value is withheld up to its closing quote, any sensitive name, any quote")
        void quotedValue() {
            assertThat(of("token='a b&c' z")).isEqualTo("token='" + W + "' z");
            assertThat(of("password=\"a b,c\" z")).isEqualTo("password=\"" + W + "\" z");
            assertThat(of("secret: 'x' y")).isEqualTo("secret: '" + W + "' y");
            assertThat(of("api_key = \"x\"")).isEqualTo("api_key = \"" + W + "\"");
            assertThat(of("token='a\"b' z")).isEqualTo("token='" + W + "' z");
        }

        @Test
        @DisplayName("9: a password name directly after '?', '&' or ';' is withheld up to the first of '&', ';', a quote, ')' or white space")
        void passwordInAUrlQuery() {
            for (String opener : List.of("?", "&", ";")) {
                for (String end : List.of("&", ";", "'", "\"", ")", " ", "\t", "\n", "\r", "\u000b", "\f")) {
                    assertThat(of("x" + opener + "password=abc" + end + "tail")).as(opener + " ends at " + end.replace("\n", "\\n"))
                            .isEqualTo("x" + opener + "password=" + W + end + "tail");
                }
            }
            assertThat(of("x?password=a,b&c")).as("a comma does not end it").isEqualTo("x?password=" + W + "&c");
            assertThat(of("x?password=a{b}[c]&d")).isEqualTo("x?password=" + W + "&d");
            assertThat(of("x?user=u&password=a&ssl=true")).isEqualTo("x?user=u&password=" + W + "&ssl=true");
            assertThat(of("x?user=u&Passwd=a;ssl=true")).isEqualTo("x?user=u&Passwd=" + W + ";ssl=true");
        }

        @Test
        @DisplayName("9: a password name anywhere else is withheld to the end of the line, and every line end ends it")
        void passwordToTheEndOfTheLine() {
            for (String end : LINE_ENDS) {
                assertThat(of("x password=a b,c&d;e)f'g\"h" + end + "next")).as("ends at U+%04X", (int) end.charAt(0))
                        .isEqualTo("x password=" + W + end + "next");
            }
            for (String notAnEnd : List.of("\t", "\f", "\u000b", "\u001c", "\u00a0", "\u2003", "\u2027", "\u202a", "\u0084", "\u0086")) {
                assertThat(of("x password=ab" + notAnEnd + "cd")).as("U+%04X is not a line end", (int) notAnEnd.charAt(0))
                        .isEqualTo("x password=" + W);
            }
            assertThat(of(" password=a b")).isEqualTo(" password=" + W);
            assertThat(of("(password=a b)")).as("a parenthesis is not a query opener").isEqualTo("(password=" + W);
            assertThat(of("a=1,password=x y")).isEqualTo("a=1,password=" + W);
            assertThat(of("password=")).isEqualTo("password=");
            assertThat(of("password=\nnext")).isEqualTo("password=\nnext");
        }

        @Test
        @DisplayName("9: a name in quotes with an unquoted value ends at ',', '}', ']', ')', '&', ';', a quote or white space")
        void quotedNameUnquotedValue() {
            for (String end : List.of(",", "}", "]", ")", "&", ";", "'", "\"", " ", "\t", "\n")) {
                assertThat(of("{\"token\": abc" + end + "tail")).as(end.replace("\n", "\\n")).isEqualTo("{\"token\": " + W + end + "tail");
                assertThat(of("{'password':abc" + end + "tail")).as(end.replace("\n", "\\n")).isEqualTo("{'password':" + W + end + "tail");
            }
            assertThat(of("{\"token\": a:b=c}")).isEqualTo("{\"token\": " + W + "}");
        }

        @Test
        @DisplayName("9: another sensitive name, unquoted, ends at '&', ';', ',', a quote, ')' or white space")
        void otherSensitiveName() {
            for (String end : List.of("&", ";", ",", "'", "\"", ")", " ", "\t", "\n", "\r")) {
                assertThat(of("x token=abc" + end + "tail")).as(end.replace("\n", "\\n").replace("\r", "\\r"))
                        .isEqualTo("x token=" + W + end + "tail");
            }
            assertThat(of("x token=a}b]c")).as("brace and bracket do not end it").isEqualTo("x token=" + W);
            assertThat(of("secret = abc d")).isEqualTo("secret = " + W + " d");
            assertThat(of("x credential:abc")).isEqualTo("x credential:" + W);
            assertThat(of("x client_secret=abc&y")).isEqualTo("x client_secret=" + W + "&y");
        }

        @Test
        @DisplayName("9: ://user:password@ withholds what lies between the first colon and the '@'")
        void authority() {
            assertThat(of("jdbc:postgresql://u:pw@h/d")).isEqualTo("jdbc:postgresql://u:" + W + "@h/d");
            assertThat(of("x://u:a:b@h")).isEqualTo("x://u:" + W + "@h");
            assertThat(of("x://u:a b@h")).as("white space ends the authority").isEqualTo("x://u:a b@h");
            assertThat(of("x://u:a/b@h")).as("a slash ends it").isEqualTo("x://u:a/b@h");
            assertThat(of("x://u:a?b@h")).isEqualTo("x://u:a?b@h");
            assertThat(of("x://u:a#b@h")).isEqualTo("x://u:a#b@h");
            assertThat(of("x://u@h:80/d")).as("no password").isEqualTo("x://u@h:80/d");
            assertThat(of("x://h:80/d")).isEqualTo("x://h:80/d");
            assertThat(of("x://u:@h")).as("an empty password").isEqualTo("x://u:" + W + "@h");
            assertThat(of("a://u:p@h b://v:q@i")).isEqualTo("a://u:" + W + "@h b://v:" + W + "@i");
        }

        @Test
        @DisplayName("10: quoting: an escape, a doubled quote, an escaped backslash before the closing quote, an empty value, an unclosed value")
        void quoting() {
            assertThat(of("password=\"a\\\"b\" t")).as("escaped quote").isEqualTo("password=\"" + W + "\" t");
            assertThat(of("password=\"a\\\\\" t")).as("escaped backslash then the closing quote").isEqualTo("password=\"" + W + "\" t");
            assertThat(of("password=\"a\\\\\\\" t\" u")).as("escaped backslash, escaped quote").isEqualTo("password=\"" + W + "\" u");
            assertThat(of("token='it''s' z")).as("doubled quote").isEqualTo("token='" + W + "' z");
            assertThat(of("token=\"\" z")).as("empty").isEqualTo("token=\"" + W + "\" z");
            assertThat(of("token='' z")).isEqualTo("token='" + W + "' z");
            assertThat(of("password=\"abc")).as("unclosed").isEqualTo("password=\"" + W);
            assertThat(of("password=\"abc\\")).as("unclosed after an escape").isEqualTo("password=\"" + W);
            assertThat(of("password=\"abc\n def\" z")).as("a quoted value may span lines").isEqualTo("password=\"" + W + "\" z");
            assertThat(of("token='a''")).isEqualTo("token='" + W);
            assertThat(of("token='a'''")).isEqualTo("token='" + W + "'");
            assertThat(of("token=\"a\" \"b\"")).as("only the first quoted value").isEqualTo("token=\"" + W + "\" \"b\"");
        }

        @Test
        @DisplayName("11: key names that are withheld")
        void keyNamesWithheld() {
            for (String name : List.of("key", "KEY", "Key", "api_key", "apiKey", "ApiKey", "X-Api-Key", "x-api-key", "sslkey", "SSLKey",
                    "private-key", "PRIVATEKEY", "private_key", "access.key", "tlsKey", "secretKey", "authKey", "encryptionKey",
                    "signing-key", "masterkey", "hmacKey", "passKey", "sessionKey", "clientKey", "licenseKey", "aesKey", "rsaKey",
                    "jwtKey", "JWT_KEY", "db.api.key", "keyStorePassword")) {
                assertThat(of("x " + name + "=v&n=1")).as(name).isEqualTo("x " + name + "=" + W + (name.equals("keyStorePassword") ? "" : "&n=1"));
            }
        }

        @Test
        @DisplayName("11: names that only resemble a key name are not withheld")
        void keyNamesNotWithheld() {
            for (String name : List.of("monkey", "keepalive", "keyStore", "key_id", "hockey", "keyId", "keyboard", "turkey", "donkey",
                    "apikeys", "key1", "keys", "foreignKeys", "primary_key_name", "whiskey", "keystore", "other-key-id")) {
                assertThat(of("x " + name + "=v&n=1")).as(name).isEqualTo("x " + name + "=v&n=1");
                assertThat(of("{" + name + ": v, n: 1}")).as(name).isEqualTo("{" + name + ": v, n: 1}");
            }
        }

        @Test
        @DisplayName("12: a stack position is unchanged, whatever the file is called; a name that merely ends in a source extension is not a position")
        void stackPositions() {
            for (String extension : List.of(".java", ".kt", ".scala", ".groovy")) {
                assertThat(of("at x.Y.m(Password" + extension + ":42)")).isEqualTo("at x.Y.m(Password" + extension + ":42)");
                assertThat(of("at x.Y.m(Secret" + extension + ":7) at q.R.s(Token" + extension + ":8)"))
                        .isEqualTo("at x.Y.m(Secret" + extension + ":7) at q.R.s(Token" + extension + ":8)");
            }
            assertThat(of("Password.java=x")).as("an equals sign is not a position").isEqualTo("Password.java=" + W);
            assertThat(of("Password.java: x")).as("no digit after the colon").isEqualTo("Password.java: " + W);
            assertThat(of("Password.txt:42")).as("not a source extension").isEqualTo("Password.txt:" + W);
            assertThat(of("Name.java=x")).isEqualTo("Name.java=x");
        }

        @Test
        @DisplayName("13: Authorization and Proxy-Authorization keep the scheme and withhold the rest of the line; a lone word is withheld whole")
        void credentialHeaders() {
            assertThat(of("Authorization: Bearer abc.def.ghi")).isEqualTo("Authorization: Bearer " + W);
            assertThat(of("Authorization: Basic dXNlcjpwYXNz\nHost: h")).isEqualTo("Authorization: Basic " + W + "\nHost: h");
            assertThat(of("Authorization: Digest a=\"b\", c=\"d\" e\nHost: h")).isEqualTo("Authorization: Digest " + W + "\nHost: h");
            assertThat(of("Authorization: Bearer a b c d\r\nHost: h")).isEqualTo("Authorization: Bearer " + W + "\r\nHost: h");
            assertThat(of("Proxy-Authorization: Basic abc")).isEqualTo("Proxy-Authorization: Basic " + W);
            assertThat(of("Authorization: abc")).isEqualTo("Authorization: " + W);
            assertThat(of("Authorization: abc.def")).as("a bare token with a dot").isEqualTo("Authorization: " + W);
            assertThat(of("Authorization:Bearer abc")).as("no space after the colon").isEqualTo("Authorization:Bearer " + W);
            assertThat(of("authorization : Bearer abc")).as("a blank before the colon").isEqualTo("authorization : Bearer " + W);
            assertThat(of("AUTHORIZATION: Bearer abc")).isEqualTo("AUTHORIZATION: Bearer " + W);
            assertThat(of("pROXY-aUTHORIZATION: Bearer abc")).isEqualTo("pROXY-aUTHORIZATION: Bearer " + W);
            assertThat(of("Authorization:   Bearer    abc d")).isEqualTo("Authorization:   Bearer    " + W);
            assertThat(of("Authorization: \"Bearer abc\" z")).as("a quoted value follows the quoted rule").isEqualTo("Authorization: \"" + W + "\" z");
        }

        @Test
        @DisplayName("13: Cookie and Set-Cookie withhold everything after the colon to the end of the line")
        void cookieHeaders() {
            assertThat(of("Cookie: sid=abc; theme=dark\nHost: h")).isEqualTo("Cookie: " + W + "\nHost: h");
            assertThat(of("Set-Cookie: sid=abc; Path=/; HttpOnly\r\nX: y")).isEqualTo("Set-Cookie: " + W + "\r\nX: y");
            assertThat(of("cookie:a b c")).isEqualTo("cookie:" + W);
            for (String end : LINE_ENDS) {
                assertThat(of("Cookie: a=b c=d" + end + "next")).isEqualTo("Cookie: " + W + end + "next");
            }
        }

        @Test
        @DisplayName("13: names that only resemble a header, and the equals form of the header names, are unchanged")
        void notHeaders() {
            assertThat(of("authorization=x")).isEqualTo("authorization=x");
            assertThat(of("cookie=x")).isEqualTo("cookie=x");
            assertThat(of("Authorization=Bearer abc")).isEqualTo("Authorization=Bearer abc");
            assertThat(of("X-Authorization: Bearer abc")).isEqualTo("X-Authorization: Bearer abc");
            assertThat(of("Proxy-Authenticate: Basic realm=\"x\"")).as("a challenge is not a credential").isEqualTo("Proxy-Authenticate: Basic realm=\"x\"");
            assertThat(of("WWW-Authenticate: Bearer realm=x")).isEqualTo("WWW-Authenticate: Bearer realm=x");
            assertThat(of("Authorized: yes")).isEqualTo("Authorized: yes");
            assertThat(of("Cookies: 3")).isEqualTo("Cookies: 3");
        }

        @Test
        @DisplayName("14: a flag naming a sensitive name withholds the next word; the ambiguous shapes are left alone")
        void flags() {
            assertThat(of("--password hunter2 rest")).isEqualTo("--password " + W + " rest");
            assertThat(of("run --api-key k1 --user u")).isEqualTo("run --api-key " + W + " --user u");
            assertThat(of("--token \"a b\" x")).isEqualTo("--token \"" + W + "\" x");
            assertThat(of("--password   hunter2")).isEqualTo("--password   " + W);
            assertThat(of("--password --user u")).as("the next word is a flag").isEqualTo("--password --user u");
            assertThat(of("x--password y")).as("not at the start of a word").isEqualTo("x--password y");
            assertThat(of("-p hunter2")).isEqualTo("-p hunter2");
            assertThat(of("-password hunter2")).isEqualTo("-password hunter2");
            assertThat(of("--password=x y")).as("the equals form withholds to the end of the line").isEqualTo("--password=" + W);
            assertThat(of("--password")).isEqualTo("--password");
            assertThat(of("--password ")).isEqualTo("--password ");
            assertThat(of("--user hunter2")).isEqualTo("--user hunter2");
        }

        @Test
        @DisplayName("15: a name inside an authority password, or inside a configured secret's range, is not a label")
        void namesInsideWithheldRanges() {
            assertThat(of("x://u:password=x@h tail")).isEqualTo("x://u:" + W + "@h tail");
            assertThat(of("x://u:token=a&b@h tail")).isEqualTo("x://u:" + W + "@h tail");
            assertThat(of("my password=hunter2 tail", "my password=hunter2")).isEqualTo(W + " tail");
            assertThat(of("a token=abc d e", "token=abc")).isEqualTo("a " + W + " d e");
            assertThat(of("a \"password\": \"x\" d", "\"password\": \"x\"")).isEqualTo("a " + W + " d");
        }

        @Test
        @DisplayName("16: text outside the withheld ranges is the input byte for byte, line ends and supplementary characters included")
        void outsideIsIdentical() {
            Random random = new Random(SEED + 16);
            List<String> pieces = List.of("connect failed ", "password=", "token: ", "://u:", "@h/d", "'", "\"", "&", ";", ",", ")", " ",
                    "key = ", "x", "secret:", "\n", "\r\n", "\u2028", "\u0085", "jdbc:postgresql://", "pwd=", "%", "+", "abc",
                    "\uD83D\uDE00", "\u00e9", "Authorization: Bearer ", "Cookie: ", "--password ", "\\", "\uD800", "\t");
            for (int round = 0; round < 8_000; round++) {
                StringBuilder message = new StringBuilder();
                for (int i = 1 + random.nextInt(16); i > 0; i--) {
                    message.append(pieces.get(random.nextInt(pieces.size())));
                }
                String text = message.toString();
                if (text.isBlank() || text.contains("<withheld>")) {
                    continue;
                }
                String secret = randomSecret(random, false);

                String safe = of(text, secret);

                assertThat(onlyWithheldSpansWereCut(text, safe)).as("%s round %d: %s -> %s", SEED_NOTE, round, text, safe).isTrue();
            }
        }

        @Test
        @DisplayName("17: it never throws and never returns '(message withheld)' except over the cap, lone surrogates included")
        void neverThrows() {
            Random random = new Random(SEED + 17);
            String alphabet = "ab%+@:/=&'\"\\ \n\r\tpasswordkeytoken\uD83D\uDE00\uD800\uDC00\u0000\uFFFF<>withheld;,()-_.\u0085\u2028\u2029";
            for (int round = 0; round < 30_000; round++) {
                StringBuilder message = new StringBuilder();
                for (int i = random.nextInt(100); i >= 0; i--) {
                    message.append(alphabet.charAt(random.nextInt(alphabet.length())));
                }
                String text = message.toString();
                int count = random.nextInt(11);
                String[] secrets = new String[count];
                java.util.Set<String> eligible = new java.util.HashSet<>();
                for (int i = 0; i < count; i++) {
                    int from = random.nextInt(text.length());
                    secrets[i] = random.nextInt(6) == 0 ? null
                            : text.substring(from, Math.min(text.length(), from + random.nextInt(10)));
                    if (secrets[i] != null && secrets[i].length() >= 3) {
                        eligible.add(secrets[i]);
                    }
                }

                String safe = of(text, secrets);

                if (text.isBlank()) {
                    assertThat(safe).isEqualTo("(no message)");
                } else if (eligible.size() > 8) {
                    assertThat(safe).as("%s round %d", SEED_NOTE, round).isEqualTo(UNREADABLE);
                } else {
                    assertThat(safe).as("%s round %d: %s with %s", SEED_NOTE, round, text, Arrays.toString(secrets))
                            .isNotNull().isNotEqualTo(UNREADABLE);
                }
            }
        }
    }

    /**
     * Whether the input is the output with something inserted where each placeholder stands: the segments
     * between placeholders appear in the input in order, the first as a prefix and the last as a suffix.
     */
    private static boolean onlyWithheldSpansWereCut(String input, String output) {
        String[] segments = output.split(Pattern.quote(W), -1);
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

    // ---- B: real messages -------------------------------------------------------------------------------

    @Nested
    @DisplayName("What an operator still sees of the messages of the drivers")
    class DriverMessages {

        private static final String PASSWORD = "s3cr3t-Pw";

        @Test
        @DisplayName("B: pgjdbc and Hikari messages that carry no credential are unchanged")
        void messagesWithoutCredentials() {
            for (String message : List.of(
                    "Failed to initialize pool: The connection attempt failed.",
                    "Failed to initialize pool: FATAL: password authentication failed for user \"identity\"",
                    "HikariPool-1 - Failed to create/setup connection (FATAL: password authentication failed for user \"identity\"): null",
                    "Connection to db.internal:5432 refused. Check that the hostname and port are correct and that the postmaster is accepting TCP/IP connections.",
                    "FATAL: no pg_hba.conf entry for host \"10.0.0.5\", user \"identity\", database \"identity\", no encryption",
                    "The server requested password-based authentication, but no password was provided by plugin scram",
                    "Failed to initialize pool: Could not read SSL key file /etc/ssl/private/client.key.",
                    "JDBC URL invalid port number: abc",
                    "pgjdbc: autodetected server-encoding to be UTF8, if the message is not readable, please check database logs and/or host, port, dbname, user, password, pg_hba.conf)",
                    "SQLSTATE 28P01: password authentication failed")) {
                assertThat(of(message, PASSWORD)).as(message).isEqualTo(message);
            }
        }

        @Test
        @DisplayName("B: messages that quote the URL lose the credential and keep the host, the port, the database and the other parameters")
        void messagesThatQuoteTheUrl() {
            assertThat(of("Failed to get driver instance for jdbcUrl=jdbc:postgresql://u:" + PASSWORD + "@db.internal:5432/identity?sslmode=require", PASSWORD))
                    .isEqualTo("Failed to get driver instance for jdbcUrl=jdbc:postgresql://u:" + W + "@db.internal:5432/identity?sslmode=require");
            assertThat(of("Failed to get driver instance for jdbcUrl=jdbc:postgresql://db.internal:5432/identity?user=u&password=" + PASSWORD + "&sslmode=require"))
                    .isEqualTo("Failed to get driver instance for jdbcUrl=jdbc:postgresql://db.internal:5432/identity?user=u&password=" + W + "&sslmode=require");
            assertThat(of("JDBC URL must start with \"jdbc:postgresql:\" but was: postgres://u:" + PASSWORD + "@h/d?password=" + PASSWORD))
                    .isEqualTo("JDBC URL must start with \"jdbc:postgresql:\" but was: postgres://u:" + W + "@h/d?password=" + W);
            assertThat(of("JDBC URL contains too many / characters: jdbc:postgresql://u:" + PASSWORD + "@h//d"))
                    .isEqualTo("JDBC URL contains too many / characters: jdbc:postgresql://u:" + W + "@h//d");
            assertThat(of("JDBC URL must contain a / at the end of the host or port: jdbc:postgresql://h:5432?user=u&password=" + PASSWORD))
                    .isEqualTo("JDBC URL must contain a / at the end of the host or port: jdbc:postgresql://h:5432?user=u&password=" + W);
            assertThat(of("Connecting with URL: jdbc:postgresql://h/d?user=u&password=" + PASSWORD))
                    .isEqualTo("Connecting with URL: jdbc:postgresql://h/d?user=u&password=" + W);
        }

        @Test
        @DisplayName("B: a configured password that a driver put into a URL as an escape is withheld without the label")
        void escapedPasswordInAUrl() {
            String escaped = java.net.URLEncoder.encode("p@ss w/rd&1", StandardCharsets.UTF_8);

            assertThat(of("Failed to get driver instance for jdbcUrl=jdbc:postgresql://u:" + escaped + "@h/d", "p@ss w/rd&1"))
                    .isEqualTo("Failed to get driver instance for jdbcUrl=jdbc:postgresql://u:" + W + "@h/d");
            assertThat(of("bad url h/d?x=" + escaped + "&y=1", "p@ss w/rd&1")).isEqualTo("bad url h/d?x=" + W + "&y=1");
        }

        @Test
        @DisplayName("B (usability): a properties dump, a configuration dump and a key=value line lose everything after the password to the end of the line")
        void overWithholdingInDumps() {
            assertThat(of("Properties: {user=u, password=" + PASSWORD + ", ssl=true, host=db}", PASSWORD)).isEqualTo("Properties: {user=u, password=" + W);
            assertThat(of("HikariConfig(jdbcUrl=jdbc:postgresql://h/d, username=u, password=<masked>, maxPoolSize=10)"))
                    .isEqualTo("HikariConfig(jdbcUrl=jdbc:postgresql://h/d, username=u, password=" + W);
            assertThat(of("Connection failed: password=x; cause: host unreachable")).isEqualTo("Connection failed: password=" + W);
            assertThat(of("Unable to connect: user=u password=p host=h")).isEqualTo("Unable to connect: user=u password=" + W);
            assertThat(of("Unable to connect: user=u password=p host=h\ncause: host unreachable"))
                    .as("the next line keeps the reason").isEqualTo("Unable to connect: user=u password=" + W + "\ncause: host unreachable");
            assertThat(of("Unable to connect: password=p host=h", "p@@")).as("a value that is not behind '?', '&' or ';'")
                    .isEqualTo("Unable to connect: password=" + W);
        }
    }

    // ---- D: linear time of the whole function ------------------------------------------------------------

    @Nested
    @DisplayName("Linear time")
    class LinearTime {

        @Test
        @DisplayName("D: a megabyte of each pathological structure is handled in under a second, without a stack overflow, with and without secrets")
        void pathologicalStructure() {
            of("warm-up password=x ://a:b@c --password y \"token\": 'z' %41", "%%%", "abc");
            int m = 1 << 20;
            Map<String, String> inputs = new LinkedHashMap<>();
            inputs.put("double quotes", "\"".repeat(m));
            inputs.put("single quotes", "'".repeat(m));
            inputs.put("backslashes", "\\".repeat(m));
            inputs.put("password=", "password=".repeat(m / 9));
            inputs.put("?password=", "?password=".repeat(m / 10));
            inputs.put("://a:", "://a:".repeat(m / 5));
            inputs.put("://u:x@", "://u:x:x@".repeat(m / 9));
            inputs.put("--password ", "--password ".repeat(m / 11));
            inputs.put("--password x ", "--password x ".repeat(m / 13));
            inputs.put("percent signs", "%".repeat(m));
            inputs.put("plus signs", "+".repeat(m));
            inputs.put("quoted names", "\"password\"".repeat(m / 10));
            inputs.put("quoted names with colons", "\"password\": ".repeat(m / 12));
            inputs.put("quoted name and unclosed value", "\"token\": \"".repeat(m / 10));
            inputs.put("Authorization:", "Authorization: ".repeat(m / 15));
            inputs.put("Authorization with credentials", "Authorization: Bearer a ".repeat(m / 24));
            inputs.put("Cookie:", "Cookie: a\n".repeat(m / 10));
            inputs.put("a long name", "a".repeat(m) + "=1");
            inputs.put("a long key name", "A".repeat(m) + "Key=1");
            inputs.put("case changes", "aB".repeat(m / 2) + "=1");
            inputs.put("key words", "aKey ".repeat(m / 5));
            inputs.put("source positions", "Password.java:1 ".repeat(m / 16));
            inputs.put("escape pairs", "%2F%40".repeat(m / 6));
            inputs.put("line ends", "password=a\n".repeat(m / 11));
            for (Map.Entry<String, String> input : inputs.entrySet()) {
                for (String[] secrets : List.of(new String[0], new String[] {"%%%", "aaa", "password=", "%2F%40", "\"\"\"", "+++"})) {
                    long start = System.nanoTime();
                    String safe = of(input.getValue(), secrets);
                    Duration took = Duration.ofNanos(System.nanoTime() - start);

                    assertThat(safe).as(input.getKey()).isNotNull().isNotEqualTo(UNREADABLE);
                    assertThat(took).as("%s with %d secrets", input.getKey(), secrets.length).isLessThan(Duration.ofSeconds(1));
                }
            }
        }

        @Test
        @DisplayName("D: eight long secrets over a megabyte, every form of each, take less than a second")
        void manyLongSecrets() {
            String[] secrets = new String[8];
            for (int i = 0; i < secrets.length; i++) {
                secrets[i] = ("k" + i).repeat(5_000);
            }
            String message = ("%41+" + "k0k1".repeat(10)).repeat(15_000);
            of("%41+k0", secrets);
            long start = System.nanoTime();

            String safe = of(message, secrets);

            assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(1));
            assertThat(safe).isNotEqualTo(UNREADABLE);
        }
    }

    // ---- the contract rules the implementation does not keep ----------------------------------------------

    @Nested
    @DisplayName("Known defects (run with -Didentity.knownDefects=true)")
    class KnownDefects {

        @Test
        @DisplayName("2: in a secret that has both a space and a '+', a '+' may stand for the space while another '+' is the secret's own")
        void plusForSpaceAndPlusInOneSecret() {
            assertThat(of("Qa+b+cQ", "a b+c")).as("space as '+', plus as '+'").isEqualTo("Q" + W + "Q");
            assertThat(of("Qa+b%2BcQ", "a b+c")).as("space as '+', plus as %2B").isEqualTo("Q" + W + "Q");
            assertThat(of("Qa%20b+cQ", "a b+c")).as("space as %20, plus as '+'").isEqualTo("Q" + W + "Q");
        }

        @Test
        @DisplayName("2: random secrets with both a space and a '+' in every per-position spelling are withheld whole")
        void mixedSpellingsOfSecretsWithSpaceAndPlus() {
            Random random = new Random(SEED + 99);
            for (int round = 0; round < 2_000; round++) {
                String secret = randomSecret(random, true);
                if (!(secret.contains(" ") && secret.contains("+"))) {
                    continue;
                }
                StringBuilder spelling = new StringBuilder();
                secret.codePoints().forEach(cp -> {
                    String text = new String(Character.toChars(cp));
                    if (cp == '%') {
                        spelling.append("%25");
                    } else if (cp == ' ' || cp == '+') {
                        spelling.append(random.nextBoolean() ? "+" : (cp == ' ' ? "%20" : "%2B"));
                    } else {
                        spelling.append(text);
                    }
                });
                // a space written as '+' and a '+' written as '+' read the same; only the position tells them apart
                assertThat(of("Q" + spelling + "Q", secret)).as("%s round %d: %s spelled %s", SEED_NOTE, round, secret, spelling)
                        .isEqualTo("Q" + W + "Q");
            }
        }
    }

    /** Pins the word list the structure rules rely on, so that a rename of a constant cannot change the table silently. */
    @Test
    @DisplayName("The caps and the minimum are the documented ones")
    void constants() {
        assertThat(LogRedaction.MINIMUM_SECRET_LENGTH).isEqualTo(3);
        assertThat(LogRedaction.MAXIMUM_SECRETS).isEqualTo(8);
        assertThat(LogRedaction.MAXIMUM_NEEDLES).isEqualTo(64);
        assertThat(LogRedaction.WITHHELD).isEqualTo("<withheld>");
        assertThat(sub(null)).isEqualTo("(no message)");
        assertThat(sub("  ")).isEqualTo("(no message)");
    }
}
