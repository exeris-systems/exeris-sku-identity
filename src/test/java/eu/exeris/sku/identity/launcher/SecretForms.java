package eu.exeris.sku.identity.launcher;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Marker secrets and the spellings in which one can reach an output. The encoders here are the test's own:
 * the redaction under test is never asked what a secret looks like.
 */
final class SecretForms {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ALPHANUMERIC = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz0123456789";

    private SecretForms() {
    }

    /** A mixed-case alphanumeric marker of {@code length} characters, at least 12; it looks like no provider's token. */
    static String marker(int length) {
        if (length < 12) {
            throw new IllegalArgumentException("a marker has at least 12 characters");
        }
        StringBuilder value = new StringBuilder("Mq");
        while (value.length() < length) {
            value.append(ALPHANUMERIC.charAt(RANDOM.nextInt(ALPHANUMERIC.length())));
        }
        return value.toString();
    }

    /** A marker of 20 characters. */
    static String marker() {
        return marker(20);
    }

    /** A marker made only of lower-case letters and digits, so that it is also a legal role name. */
    static String lowerCaseMarker() {
        StringBuilder value = new StringBuilder("mq");
        while (value.length() < 20) {
            value.append(LOWER.charAt(RANDOM.nextInt(LOWER.length())));
        }
        return value.toString();
    }

    /** A marker with characters that a URL escapes and a shell would not leave alone. */
    static String markerWithSpecials() {
        String head = marker(8 + 4);
        return head.substring(0, 6) + "+/&@=%" + head.substring(6) + " x";
    }

    /** A marker of digits only, as a numeric setting would hold. */
    static String numericMarker() {
        StringBuilder value = new StringBuilder("7");
        while (value.length() < 15) {
            value.append((char) ('0' + RANDOM.nextInt(10)));
        }
        return value.toString();
    }

    /**
     * Every spelling of the secret an output could hold: the literal text, the percent-encoded text in upper-
     * and lower-case hexadecimal (also with a space spelled as {@code +} and as {@code %20}), and the Base64
     * and Base64url text of its UTF-8 bytes with and without padding, in each of the three alignments a
     * Base64 run can have inside a longer payload.
     */
    static List<String> forms(String secret) {
        return forms(secret, true);
    }

    /** The spellings a redaction is documented to withhold: everything but the cuts of a longer Base64 payload. */
    static List<String> contiguousForms(String secret) {
        return forms(secret, false);
    }

    private static List<String> forms(String secret, boolean withAlignments) {
        Set<String> forms = new LinkedHashSet<>();
        forms.add(secret);
        String plus = URLEncoder.encode(secret, StandardCharsets.UTF_8);
        forms.add(plus);
        forms.add(plus.replace("+", "%20"));
        forms.add(lowerHex(plus));
        forms.add(lowerHex(plus.replace("+", "%20")));
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        for (Base64.Encoder encoder : List.of(Base64.getEncoder(), Base64.getEncoder().withoutPadding(),
                Base64.getUrlEncoder(), Base64.getUrlEncoder().withoutPadding())) {
            forms.add(encoder.encodeToString(bytes));
            if (withAlignments) {
                forms.addAll(alignments(encoder, bytes));
            }
        }
        forms.removeIf(String::isEmpty);
        return new ArrayList<>(forms);
    }

    /**
     * The stable middle of the Base64 text of the bytes when one or two other bytes precede them, which is
     * how the secret reads inside a longer payload: the first characters depend on the preceding bytes and
     * the last two on what follows, so both ends are cut.
     */
    private static List<String> alignments(Base64.Encoder encoder, byte[] bytes) {
        List<String> shifted = new ArrayList<>();
        for (int lead = 1; lead <= 2; lead++) {
            byte[] padded = new byte[lead + bytes.length];
            System.arraycopy(bytes, 0, padded, lead, bytes.length);
            String text = encoder.encodeToString(padded);
            int start = lead == 1 ? 2 : 3;
            int end = text.length() - 4;
            if (end - start >= 8) {
                shifted.add(text.substring(start, end));
            }
        }
        return shifted;
    }

    /** The same percent-encoding with lower-case hexadecimal digits. */
    private static String lowerHex(String encoded) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < encoded.length(); i++) {
            char c = encoded.charAt(i);
            if (c == '%' && i + 2 < encoded.length() + 0) {
                out.append(c).append(encoded.substring(i + 1, i + 3).toLowerCase(Locale.ROOT));
                i += 2;
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    /**
     * The lines of the output that hold the secret in any spelling, each with every spelling replaced by
     * {@code <name>}, so that the lines can be shown in a failure message without printing the secret.
     */
    static List<String> leaks(String output, String name, String secret) {
        List<String> found = new ArrayList<>();
        List<String> forms = forms(secret);
        for (String line : output.split("\\R", -1)) {
            boolean leaking = forms.stream().anyMatch(line::contains);
            if (leaking) {
                String shown = line;
                for (String form : forms) {
                    shown = shown.replace(form, "<" + name + ">");
                }
                found.add(shown);
            }
        }
        return found;
    }

    /** Fails, showing the offending lines with the secrets named, when the output holds a secret in any spelling. */
    static void assertNoLeaks(String output, String what, java.util.Map<String, String> secrets) {
        List<String> all = new ArrayList<>();
        secrets.forEach((name, secret) -> all.addAll(leaks(output, name, secret)));
        assertThat(all).as(what + ": lines of the output that hold a secret").isEmpty();
    }

    /** Fails when the output holds the secret in any spelling. */
    static void assertAbsent(String output, String what, String secret) {
        for (String form : forms(secret)) {
            assertThat(output).as(what + ": the output holds the secret as '" + (form.equals(secret) ? "<MARKER>" : "<ENCODED MARKER>")
                    + "' (" + (form.equals(secret) ? "literal" : "encoded form of length " + form.length()) + ")")
                    .doesNotContain(form);
        }
    }

    /** Fails when the output holds the secret in any spelling, or a run of {@code length} characters from either end of it. */
    static void assertNoFragments(String output, String what, String secret, int length) {
        assertAbsent(output, what, secret);
        assertThat(secret.length()).isGreaterThanOrEqualTo(2 * length);
        assertThat(output).as(what + ": the output holds the first " + length + " characters of the secret")
                .doesNotContain(secret.substring(0, length));
        assertThat(output).as(what + ": the output holds the last " + length + " characters of the secret")
                .doesNotContain(secret.substring(secret.length() - length));
    }
}
