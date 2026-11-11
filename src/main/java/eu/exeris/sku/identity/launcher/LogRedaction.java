package eu.exeris.sku.identity.launcher;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Makes a message the kernel or a driver produced safe to write to the log. The kernel's text is what an
 * operator needs, for instance the licence gate's code and reason, but a connection failure can quote the
 * JDBC URL it was given, and that URL is operator input that may carry credentials.
 *
 * <p>The function runs in two stages, always in this order, so that its result does not depend on the order
 * of the secrets or on which pattern happens to match first.
 *
 * <ol>
 *   <li><b>Configured secrets.</b> Every occurrence of every configured secret of at least
 *       {@link #MINIMUM_SECRET_LENGTH} characters is withheld, as a literal and wherever it appears, together
 *       with its URL-encoded forms (the form-encoding of {@link URLEncoder} with {@code +} or {@code %20} for
 *       a space, each with upper-case or lower-case hexadecimal digits). The occurrences of all secrets are
 *       collected on the original text and their union is withheld, so the result is the same for any order
 *       of the secrets, a secret that contains {@code &}, {@code @} or {@code /} is withheld whole, and one
 *       secret can never match inside the placeholder another one left. Base64 forms are not handled: no
 *       message this service logs carries the database password in that form, and the Base64 of a secret
 *       embedded in a longer payload cannot be recognised.</li>
 *   <li><b>Structure.</b> The password of a {@code user:password@host} authority, and the value of a
 *       labelled parameter, are withheld whether or not they are configured secrets. A label is a name, a
 *       maximal run of letters, digits, {@code _}, {@code .} and {@code -}, that contains one of
 *       {@link #SENSITIVE_WORDS} in any case and is followed, after optional blanks, by {@code =} or
 *       {@code :}. The value is the quoted text up to the closing quote (to the end of the message when it
 *       is not closed), or else the run up to {@code &}, {@code ;}, white space, {@code ,}, a quote or
 *       {@code )}.</li>
 * </ol>
 *
 * <p>Invariants:
 * <ul>
 *   <li>It never throws; when it cannot finish it returns a fixed text that holds none of the message.</li>
 *   <li>Its time and memory are linear in the length of the message plus the length of the secrets: the
 *       matching is a single left-to-right scan with no backtracking.</li>
 *   <li>It is idempotent: {@code of(of(x, s), s)} equals {@code of(x, s)}.</li>
 *   <li>No configured secret of at least {@link #MINIMUM_SECRET_LENGTH} characters appears in the result.</li>
 *   <li>A secret shorter than {@link #MINIMUM_SECRET_LENGTH} is not replaced where it merely occurs: a
 *       one- or two-character secret would blank every such character of every message, and the result would
 *       no longer say what failed. It is still withheld wherever it is the value of a label or the password
 *       of an authority, because that stage does not depend on the secret.</li>
 *   <li>A secret that is a part of {@link #WITHHELD} is not replaced where it occurs: it would damage the
 *       placeholders, and it is public text.</li>
 *   <li>Text outside a withheld value is not altered.</li>
 * </ul>
 *
 * <p>The sensitive words and why each is in: {@code password}, {@code passwd} and {@code pwd} are the
 * names drivers and tools use for a password, and {@code passphrase} for a key's; {@code secret} covers
 * client secrets and {@code secretKey}; {@code token} covers access and session tokens; {@code credential}
 * covers {@code credentials} and {@code credentialsProvider}-style values; {@code key} covers
 * {@code apiKey}, {@code accessKey}, {@code privateKey} and {@code keyStorePassword}-style names. Rejected
 * as too broad: {@code auth}, which also names {@code authenticationPluginClassName}, {@code authority} and
 * {@code author}, none of them secret; {@code authorization}, whose value is a scheme followed by the
 * credential, so withholding only the first word would give a false sense of safety, and which no database
 * message carries; {@code pass}, which is a part of {@code bypass} and {@code passthrough}.
 */
final class LogRedaction {

    /** What replaces a withheld value. */
    static final String WITHHELD = "<withheld>";

    /**
     * The shortest configured secret that is withheld wherever it occurs. Three characters is the least that
     * still keeps a credential-shaped string such as {@code a@b} out of the log while an ordinary message
     * keeps its words; a shorter secret is withheld only where the structure names it.
     */
    static final int MINIMUM_SECRET_LENGTH = 3;

    /** Parts of a parameter name that make its value a secret, matched in any case. */
    static final List<String> SENSITIVE_WORDS = List.of(
            "password", "passwd", "pwd", "passphrase", "secret", "token", "credential", "key");

    private static final String UNREADABLE = "(message withheld)";

    private LogRedaction() {
    }

    /**
     * Returns the message with every credential withheld.
     *
     * @param message the message of an exception; may be {@code null}
     * @param secrets values that must never appear, such as the database password; {@code null}, the array
     *                itself, empty values and values shorter than {@link #MINIMUM_SECRET_LENGTH} are not
     *                replaced globally
     * @return the message to log; a placeholder when there was none
     */
    static String of(String message, String... secrets) {
        if (message == null || message.isBlank()) {
            return "(no message)";
        }
        try {
            String safe = withholdSecrets(message, secrets);
            safe = withholdAuthorityPasswords(safe);
            return withholdLabelledValues(safe);
        } catch (RuntimeException e) {
            return UNREADABLE;
        }
    }

    // ---- stage 1: configured secrets -------------------------------------------------------------------

    private static String withholdSecrets(String text, String[] secrets) {
        if (secrets == null) {
            return text;
        }
        Set<String> forms = new LinkedHashSet<>();
        for (String secret : secrets) {
            if (secret != null && secret.length() >= MINIMUM_SECRET_LENGTH && !WITHHELD.contains(secret)) {
                forms.add(secret);
                String encoded = URLEncoder.encode(secret, StandardCharsets.UTF_8);
                for (String form : new String[] {encoded, encoded.replace("+", "%20")}) {
                    forms.add(form);
                    forms.add(lowerCaseEscapes(form));
                }
            }
        }
        if (forms.isEmpty()) {
            return text;
        }
        int length = text.length();
        int[] delta = new int[length + 1];
        for (String form : forms) {
            markOccurrences(text, form, delta);
        }
        StringBuilder out = new StringBuilder(length);
        int covered = 0;
        boolean inside = false;
        for (int i = 0; i < length; i++) {
            covered += delta[i];
            if (covered > 0) {
                if (!inside) {
                    out.append(WITHHELD);
                    inside = true;
                }
            } else {
                inside = false;
                out.append(text.charAt(i));
            }
        }
        return out.toString();
    }

    /** Knuth-Morris-Pratt: adds +1 at each occurrence's start and -1 after its end, overlaps included. */
    private static void markOccurrences(String text, String pattern, int[] delta) {
        int m = pattern.length();
        int[] fallback = new int[m];
        for (int i = 1, k = 0; i < m; i++) {
            while (k > 0 && pattern.charAt(i) != pattern.charAt(k)) {
                k = fallback[k - 1];
            }
            if (pattern.charAt(i) == pattern.charAt(k)) {
                k++;
            }
            fallback[i] = k;
        }
        for (int i = 0, k = 0; i < text.length(); i++) {
            while (k > 0 && text.charAt(i) != pattern.charAt(k)) {
                k = fallback[k - 1];
            }
            if (text.charAt(i) == pattern.charAt(k)) {
                k++;
            }
            if (k == m) {
                delta[i - m + 1]++;
                delta[i + 1]--;
                k = fallback[k - 1];
            }
        }
    }

    private static String lowerCaseEscapes(String encoded) {
        StringBuilder out = new StringBuilder(encoded.length());
        for (int i = 0; i < encoded.length(); i++) {
            char c = encoded.charAt(i);
            out.append(c);
            if (c == '%' && i + 2 < encoded.length()) {
                out.append(Character.toLowerCase(encoded.charAt(i + 1)));
                out.append(Character.toLowerCase(encoded.charAt(i + 2)));
                i += 2;
            }
        }
        return out.toString();
    }

    // ---- stage 2: structure ----------------------------------------------------------------------------

    /** {@code ://user:password@}: the password is whatever lies between the first colon and the {@code @}. */
    private static String withholdAuthorityPasswords(String text) {
        int n = text.length();
        StringBuilder out = new StringBuilder(n);
        int i = 0;
        while (i < n) {
            int scheme = text.indexOf("://", i);
            if (scheme < 0) {
                break;
            }
            int user = scheme + 3;
            int colon = user;
            while (colon < n && !isUserInfoStop(text.charAt(colon)) && text.charAt(colon) != ':') {
                colon++;
            }
            int at = colon + 1;
            if (colon < n && text.charAt(colon) == ':') {
                // The password may itself hold ':'; it ends at the first '@' reached before a delimiter.
                while (at < n && !isUserInfoStop(text.charAt(at))) {
                    at++;
                }
            }
            if (colon < n && text.charAt(colon) == ':' && at < n && text.charAt(at) == '@') {
                out.append(text, i, colon + 1).append(WITHHELD);
                i = at;
            } else {
                out.append(text, i, user);
                i = user;
            }
        }
        out.append(text, i, n);
        return out.toString();
    }

    private static boolean isUserInfoStop(char c) {
        return c == '/' || c == '@' || c == '?' || c == '#' || Character.isWhitespace(c);
    }

    private static String withholdLabelledValues(String text) {
        int n = text.length();
        StringBuilder out = new StringBuilder(n);
        int i = 0;
        while (i < n) {
            if (!isNameChar(text.charAt(i))) {
                out.append(text.charAt(i++));
                continue;
            }
            int end = i;
            while (end < n && isNameChar(text.charAt(end))) {
                end++;
            }
            out.append(text, i, end);
            int separator = skipBlanks(text, end);
            if (!isSensitive(text, i, end) || separator >= n
                    || (text.charAt(separator) != '=' && text.charAt(separator) != ':')) {
                i = end;
                continue;
            }
            int value = skipBlanks(text, separator + 1);
            out.append(text, end, value);
            if (value >= n) {
                i = n;
            } else if (text.charAt(value) == '\'' || text.charAt(value) == '"') {
                char quote = text.charAt(value);
                int close = text.indexOf(quote, value + 1);
                out.append(quote).append(WITHHELD);
                if (close < 0) {
                    i = n;
                } else {
                    out.append(quote);
                    i = close + 1;
                }
            } else {
                int stop = value;
                while (stop < n && !isValueStop(text.charAt(stop))) {
                    stop++;
                }
                if (stop > value) {
                    out.append(WITHHELD);
                }
                i = stop;
            }
        }
        return out.toString();
    }

    private static int skipBlanks(String text, int from) {
        int i = from;
        while (i < text.length() && (text.charAt(i) == ' ' || text.charAt(i) == '\t')) {
            i++;
        }
        return i;
    }

    private static boolean isNameChar(char c) {
        return c == '_' || c == '.' || c == '-' || Character.isLetterOrDigit(c);
    }

    private static boolean isValueStop(char c) {
        return c == '&' || c == ';' || c == ',' || c == '\'' || c == '"' || c == ')' || Character.isWhitespace(c);
    }

    private static boolean isSensitive(String text, int from, int to) {
        for (String word : SENSITIVE_WORDS) {
            for (int p = from; p + word.length() <= to; p++) {
                if (text.regionMatches(true, p, word, 0, word.length())) {
                    return true;
                }
            }
        }
        return false;
    }
}
