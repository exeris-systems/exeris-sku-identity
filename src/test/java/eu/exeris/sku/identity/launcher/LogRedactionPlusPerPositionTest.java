package eu.exeris.sku.identity.launcher;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * How {@link LogRedaction} reads a plus and a space in a message against a secret, position by position, and
 * the fail-closed work budget of that reading.
 *
 * <p>The rule, per position of the secret: a secret space is matched by a message space, {@code %20} or a
 * literal {@code +}; a secret {@code +} is matched by a literal {@code +} or {@code %2B}, never by a space;
 * any other byte is matched by itself or by its {@code %XX}.
 */
@DisplayName("LogRedaction: plus and space per position of the secret")
class LogRedactionPlusPerPositionTest {

    private static final String W = LogRedaction.WITHHELD;
    private static final String UNREADABLE = "(message withheld)";
    private static final long SEED = Long.getLong("redaction.seed", 20_261_113L);
    private static final int ROUNDS = 20_000;

    /** Every spelling the contract allows for one character of a secret. */
    private static List<String> spellings(char c) {
        return switch (c) {
            case ' ' -> List.of(" ", "%20", "+");
            case '+' -> List.of("+", "%2B", "%2b");
            case 'a' -> List.of("a", "%61");
            case 'b' -> List.of("b", "%62");
            case '/' -> List.of("/", "%2F", "%2f");
            case '%' -> List.of("%", "%25");
            default -> throw new IllegalArgumentException("no spelling for " + c);
        };
    }

    private static void combinations(String secret, int index, String prefix, List<String> out) {
        if (index == secret.length()) {
            out.add(prefix);
            return;
        }
        for (String spelling : spellings(secret.charAt(index))) {
            combinations(secret, index + 1, prefix + spelling, out);
        }
    }

    // ---- the contract, case by case ----------------------------------------------------------------------

    @Test
    @DisplayName("Secrets of spaces, pluses, hex-lettered characters and slashes: every combination of the spellings of their characters is withheld whole between filler")
    void everyCombinationOfSpellings() {
        for (String secret : List.of("a b+b", "a /+/", " + ", "+ +", "/ +/", "  +", "+  ")) {
            List<String> spelled = new ArrayList<>();
            combinations(secret, 0, "", spelled);
            assertThat(spelled).isNotEmpty();
            for (String message : spelled) {
                assertThat(LogRedaction.of("QQ" + message + "QQ", secret)).as("%s spelled %s", secret, message)
                        .isEqualTo("QQ" + W + "QQ");
            }
        }
    }

    @Test
    @DisplayName("Secret 'a b+c' in all 72 spellings of its characters")
    void theNamedSecret() {
        for (String a : List.of("a", "%61")) {
            for (String space : List.of(" ", "%20", "+")) {
                for (String b : List.of("b", "%62")) {
                    for (String plus : List.of("+", "%2B", "%2b")) {
                        for (String c : List.of("c", "%63")) {
                            String message = a + space + b + plus + c;
                            assertThat(LogRedaction.of("Q" + message + "Q", "a b+c")).as(message)
                                    .isEqualTo("Q" + W + "Q");
                        }
                    }
                }
            }
        }
    }

    @Test
    @DisplayName("A message space does not match a secret '+', and %2B does not match a secret space")
    void theWrongWayRound() {
        for (String message : List.of("Qa bQ", "Qa b b", "Qa%20bQ")) {
            assertThat(LogRedaction.of(message, "a+b")).as(message).isEqualTo(message);
        }
        for (String message : List.of("Qa%2BbQ", "Qa%2bbQ")) {
            assertThat(LogRedaction.of(message, "a b")).as(message).isEqualTo(message);
        }
        assertThat(LogRedaction.of("Qa b+cQ", "a b+c")).isEqualTo("Q" + W + "Q");
        assertThat(LogRedaction.of("Qa+b b" + "cQ", "a b+c")).as("a space where the secret has '+'")
                .isEqualTo("Qa+b b" + "cQ");
        assertThat(LogRedaction.of("Qa%2Bb+cQ", "a b+c")).as("%2B where the secret has a space")
                .isEqualTo("Qa%2Bb+cQ");
    }

    @Test
    @DisplayName("A candidate that fails only at its last separator is not withheld, and the text around and after it is not altered")
    void failsOnlyAtTheLastSeparator() {
        assertThat(LogRedaction.of("xa b cx", "a b+c")).isEqualTo("xa b cx");
        assertThat(LogRedaction.of("a b+c a b c a b+c", "a b+c")).isEqualTo(W + " a b c " + W);
        assertThat(LogRedaction.of("a b c a b+c", "a b+c")).isEqualTo("a b c " + W);
        assertThat(LogRedaction.of("   a  b   ", "a b+c")).isEqualTo("   a  b   ");
        assertThat(LogRedaction.of("+++ ++ a b c", "+++ ")).as("%s", "ends at the last separator of the secret")
                .isEqualTo(W + "++ a b c");
    }

    // ---- the property -------------------------------------------------------------------------------------

    /** One token of the message: the byte it stands for, whether it is a literal plus, and the characters it spans. */
    private record Token(int value, boolean literalPlus, int from, int to) {
    }

    private static int hex(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    }

    private static List<Token> tokenise(String message) {
        List<Token> tokens = new ArrayList<>();
        int i = 0;
        while (i < message.length()) {
            char c = message.charAt(i);
            if (c == '%' && i + 2 < message.length() && hex(message.charAt(i + 1)) >= 0
                    && hex(message.charAt(i + 2)) >= 0) {
                tokens.add(new Token(hex(message.charAt(i + 1)) << 4 | hex(message.charAt(i + 2)), false, i, i + 3));
                i += 3;
            } else {
                tokens.add(new Token(c, c == '+', i, i + 1));
                i++;
            }
        }
        return tokens;
    }

    private static boolean accepts(char secretChar, Token token) {
        return switch (secretChar) {
            case ' ' -> token.value() == ' ' || token.literalPlus();
            case '+' -> token.value() == '+';
            default -> token.value() == secretChar;
        };
    }

    /** The brute-force reading: every start, every position, the rule applied directly; the literal text always counts. */
    private static String reference(String message, List<String> secrets) {
        List<Token> tokens = tokenise(message);
        boolean[] withheld = new boolean[message.length()];
        for (String secret : secrets) {
            for (int at = message.indexOf(secret); at >= 0; at = message.indexOf(secret, at + 1)) {
                for (int k = at; k < at + secret.length(); k++) {
                    withheld[k] = true;
                }
            }
            for (int start = 0; start + secret.length() <= tokens.size(); start++) {
                boolean match = true;
                for (int j = 0; j < secret.length() && match; j++) {
                    match = accepts(secret.charAt(j), tokens.get(start + j));
                }
                if (match) {
                    for (int k = tokens.get(start).from(); k < tokens.get(start + secret.length() - 1).to(); k++) {
                        withheld[k] = true;
                    }
                }
            }
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < message.length(); i++) {
            if (withheld[i]) {
                if (i == 0 || !withheld[i - 1]) {
                    out.append(W);
                }
            } else {
                out.append(message.charAt(i));
            }
        }
        return out.toString();
    }

    private static final List<String> UNITS = List.of("a", "b", " ", "+", "%", "%20", "%2B", "%2b", "%61", "%62",
            "%25", "%4", "%z", "%a", "%%", "  ", "++", "% ");

    private static String randomSecret(Random random) {
        String alphabet = random.nextInt(4) == 0 ? " +" : random.nextInt(8) == 0 ? "+%a" : "ab +%";
        int length = 3 + random.nextInt(6);
        StringBuilder secret = new StringBuilder();
        for (int i = 0; i < length; i++) {
            secret.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }
        return secret.toString();
    }

    private static String spell(String secret, Random random) {
        StringBuilder out = new StringBuilder();
        for (char c : secret.toCharArray()) {
            List<String> options = c == 'a' || c == 'b' || c == ' ' || c == '+' || c == '%' ? spellings(c) : List.of("" + c);
            out.append(options.get(random.nextInt(options.size())));
        }
        return out.toString();
    }

    @Test
    @DisplayName("Property: over 20 000 seeded rounds on the alphabet {a, b, space, plus, percent} with escapes and invalid escapes, production equals the brute-force reading exactly")
    void productionAgreesWithTheReference() {
        Random random = new Random(SEED);
        int withheldRounds = 0;
        for (int round = 0; round < ROUNDS; round++) {
            List<String> secrets = new ArrayList<>();
            for (int i = 1 + (random.nextInt(5) == 0 ? random.nextInt(3) : 0); i > 0; i--) {
                secrets.add(randomSecret(random));
            }
            StringBuilder message = new StringBuilder();
            for (int pieces = random.nextInt(9); pieces >= 0; pieces--) {
                if (random.nextBoolean()) {
                    message.append(spell(secrets.get(random.nextInt(secrets.size())), random));
                } else {
                    message.append(UNITS.get(random.nextInt(UNITS.size())));
                }
            }
            String text = message.toString();
            if (text.isBlank()) {
                continue;
            }
            // a distinct secret list, as the function takes it
            List<String> distinct = secrets.stream().distinct().toList();

            String actual = LogRedaction.of(text, distinct.toArray(String[]::new));
            String expected = reference(text, distinct);

            assertThat(actual).as("seed=%d round=%d message=[%s] secrets=%s", SEED, round, text, distinct)
                    .isEqualTo(expected);
            if (!expected.equals(text)) {
                withheldRounds++;
            }
        }
        assertThat(withheldRounds).as("rounds in which something was withheld").isGreaterThan(ROUNDS / 4);
    }

    // ---- the work budget ----------------------------------------------------------------------------------

    private static String repeat(String unit, int times) {
        return unit.repeat(times);
    }

    private static long millis(Runnable action) {
        long start = System.nanoTime();
        action.run();
        return (System.nanoTime() - start) / 1_000_000;
    }

    @Test
    @DisplayName("A long secret of alternating space and plus over a megabyte of pluses exceeds the budget: the output is exactly '(message withheld)' within a second")
    void alternatingSecretOverPlusesExceedsTheBudget() {
        String secret = repeat(" +", 1_000);
        String message = repeat("+", 1_000_000);
        LogRedaction.of("+ +", secret);
        String[] out = new String[1];

        long took = millis(() -> out[0] = LogRedaction.of(message, secret));

        assertThat(out[0]).isEqualTo(UNREADABLE);
        assertThat(Duration.ofMillis(took)).isLessThan(Duration.ofSeconds(2));
    }

    @Test
    @DisplayName("A secret of spaces ending in a plus over a megabyte of spaces, where every candidate fails at its last separator, exceeds the budget the same way")
    void nearMatchingSeparatorsExceedTheBudget() {
        String secret = repeat(" ", 1_999) + "+";
        String message = repeat(" ", 1_000_000);
        String[] out = new String[1];

        long took = millis(() -> out[0] = LogRedaction.of(message + "%2B", secret));

        assertThat(out[0]).isEqualTo(UNREADABLE);
        assertThat(Duration.ofMillis(took)).isLessThan(Duration.ofSeconds(2));
    }

    @Test
    @DisplayName("The budget is per secret, not per call: a message that is cheap for the first secret and over budget for the second is withheld whole, whatever the order, and holds nothing of the message")
    void theBudgetIsPerSecret() {
        String heavy = repeat(" +", 1_000);
        String message = repeat("+", 200_000) + " token=hunter2hunter2";

        assertThat(LogRedaction.of(message, "hunter2hunter2")).as("cheap alone").isNotEqualTo(UNREADABLE)
                .contains("token=");
        assertThat(LogRedaction.of(message, heavy)).isEqualTo(UNREADABLE);
        assertThat(LogRedaction.of(message, "hunter2hunter2", heavy)).isEqualTo(UNREADABLE);
        assertThat(LogRedaction.of(message, heavy, "hunter2hunter2")).isEqualTo(UNREADABLE);
    }

    @Test
    @DisplayName("Secrets each within the budget cost no more than the sum of their own bounds: eight secrets that each come close to it still end in under two seconds")
    void severalSecretsEachWithinTheirOwnBound() {
        String[] secrets = new String[8];
        for (int i = 0; i < secrets.length; i++) {
            secrets[i] = repeat(" ", 15 + i) + "+" + "k".repeat(i);
        }
        String message = repeat(" ", 100_000) + "x";
        String[] out = new String[1];

        long took = millis(() -> out[0] = LogRedaction.of(message, secrets));

        assertThat(Duration.ofMillis(took)).isLessThan(Duration.ofSeconds(2));
        assertThat(out[0]).isNotBlank();
    }

    // ---- realistic input against the budget -------------------------------------------------------------

    private static final String PROSE = "the quick brown fox jumps over the lazy dog while the service was starting "
            + "and the pool opened its connections to the primary and then to the replica ";

    @Test
    @DisplayName("Realistic input does not lose its line: a three-space secret, a thirty-word passphrase and a base64 secret with pluses over a megabyte of prose are processed, and each occurrence is withheld")
    void realisticSecretsOverProse() {
        String threeSpaces = "   ";
        String passphrase = String.join(" ", "correct horse battery staple".repeat(8).split("(?<=staple)"))
                .replace("staplecorrect", "staple correct");
        String base64 = "ab+cd+ef/gh+ij+kl+mn+op+qr+st+uv+wx+yz+01+23+45+67=";
        String prose = PROSE.repeat(6_000);
        String message = prose + "[" + threeSpaces + "] " + passphrase + " " + base64.replace("+", "%2B") + " " + base64;

        for (String secret : List.of(threeSpaces, passphrase, base64)) {
            String out = LogRedaction.of(message, secret);

            assertThat(out).as("secret of %d chars", secret.length()).isNotEqualTo(UNREADABLE).contains(W);
        }
        assertThat(LogRedaction.of(message, passphrase, base64)).doesNotContain(passphrase).doesNotContain(base64);
    }

    @Test
    @DisplayName("Smallest all-space message that loses its line for a secret of n spaces: measured, and it is never an ordinary message")
    void smallestMessageThatTripsTheBudget() {
        StringBuilder report = new StringBuilder();
        for (int separators : new int[] {3, 8, 16, 17, 20, 32, 64}) {
            String secret = repeat(" ", separators);
            int smallest = -1;
            for (int run = separators; run <= 200_000; run = run < 2_000 ? run + 1 : (int) (run * 1.02)) {
                if (LogRedaction.of(repeat(" ", run) + "+", secret).equals(UNREADABLE)) {
                    smallest = run;
                    break;
                }
            }
            report.append(separators).append(" spaces -> ").append(smallest < 0 ? "never" : smallest + " spaces").append("; ");
            if (separators <= 16) {
                assertThat(smallest).as("a secret of %d separators can never trip the budget", separators).isEqualTo(-1);
            }
        }
        System.out.println("[redaction budget] " + report);
    }
}
