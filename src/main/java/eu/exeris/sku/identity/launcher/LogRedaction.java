package eu.exeris.sku.identity.launcher;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.BitSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Makes a message the kernel or a driver produced safe to write to the log. The kernel's text is what an
 * operator needs, for instance the licence gate's code and reason, but a connection failure can quote the
 * JDBC URL it was given, and that URL is operator input that may carry credentials.
 *
 * <h2>What is guaranteed, and what is best effort</h2>
 *
 * <p><b>Configured secrets: guaranteed.</b> Every occurrence of a configured secret of at least
 * {@link #MINIMUM_SECRET_LENGTH} characters in the input message is replaced by {@link #WITHHELD}, in each of
 * these forms, so that the guarantee does not depend on how a driver formatted the value:
 * <ul>
 *   <li>the literal text;</li>
 *   <li>with percent-escapes decoded, position by position: any mix of literal characters and
 *       {@code %XX} escapes (upper-case or lower-case hexadecimal digits) of the secret's UTF-8 bytes. The
 *       choice of spelling is made at each position of the secret on its own: a literal {@code +} in the
 *       message stands for a space exactly where the secret has a space, and a {@code +} in the secret
 *       matches a literal {@code +} or {@code %2B} (never a space), so a message may spell one space as
 *       {@code +} and another {@code +} as itself;</li>
 *   <li>the Base64 and Base64url encodings of the secret's UTF-8 bytes, with and without padding, as a
 *       contiguous run anywhere in the message.</li>
 * </ul>
 * Matching is case-sensitive: a password is case-sensitive, so a differently cased string is another
 * string, and case is not folded. A configured secret that a driver split across a line break, or that was
 * encoded twice, or that is embedded in a longer Base64 payload, is not recognised.
 *
 * <p>The guarantee is over the <em>input</em>. The literal text of {@link #WITHHELD} that the function writes
 * is not an occurrence of anything: a secret that is a part of the placeholder (for example {@code held}) is
 * replaced wherever it occurs in the input message, and the placeholder is not re-scanned. Consequently the
 * function is not idempotent for a secret that overlaps the placeholder's characters, and it is not
 * idempotent in general either: withholding a value removes the delimiters that were inside it, which can
 * change where a later reading of the same message finds an authority or a value ending. Idempotence is not
 * an invariant, the security property is.
 *
 * <p>The work is bounded. At most {@value #MAXIMUM_SECRETS} distinct configured secrets of at least the
 * minimum length are accepted, and a secret has at most six needles (its literal text, its distinct Base64
 * forms and its decoded view). Beyond the secret cap,
 * or when confirming the candidates of one secret in the decoded view would cost more than a fixed multiple
 * of the lengths of the message and the secret, the function fails closed: it returns the fixed text
 * {@code (message withheld)}, never an unredacted message.
 *
 * <p><b>Other credentials in third-party text: best effort.</b> The structure stage below withholds what it
 * recognises by shape. It does not know the secret, so a shape it does not cover passes through. Treat it as
 * a net for the common shapes, not as a guarantee.
 *
 * <h2>How it works</h2>
 *
 * <p>Both stages read the original message and only record which character ranges are withheld; the result is
 * rendered once, a maximal run of withheld characters becoming one {@link #WITHHELD}. A placeholder is never
 * input to a later scan, so no stage can cut into one, read it as a name or a value, or be confused by it,
 * and no configured secret has to be exempted for fear of damaging a placeholder. The second stage treats a
 * character the first withheld as part of a value, never as a delimiter, so a secret that contains
 * {@code &}, {@code @}, {@code /}, a quote or a blank is withheld whole and the rest of the value that
 * follows it goes with it; and as a character that is not part of a name, exactly as the placeholder that
 * replaces it is not, so that a name next to a withheld secret is found the same way whether or not the
 * secret has already been replaced.
 *
 * <h2>The structure stage</h2>
 *
 * <p><i>Authority.</i> In {@code ://user:password@host} the password is whatever lies between the first colon
 * after the scheme and the first {@code @} reached before {@code /}, {@code ?}, {@code #} or white space.
 *
 * <p><i>Labels.</i> A <em>name</em> is a maximal run of letters, digits, {@code _}, {@code .} and
 * {@code -}. A name is a <em>password name</em> when it contains {@code password}, {@code passwd},
 * {@code pwd} or {@code passphrase} in any case, and a <em>sensitive name</em> when it is a password name or
 * contains {@code secret}, {@code token} or {@code credential} in any case, or ends in a key word. A name
 * <em>ends in a key word</em> when its last component is {@code key}, or a known prefix followed by
 * {@code key}: components are separated by {@code _}, {@code .} and {@code -} and by a lower-to-upper case
 * change or an upper-case run ending before a lower-case letter, so {@code key}, {@code KEY}, {@code api_key},
 * {@code apiKey}, {@code X-Api-Key}, {@code private-key}, {@code SSLKey} and {@code sslkey} end in a key word,
 * while {@code monkey}, {@code keepalive}, {@code keyStore}, {@code key_id} and {@code hockey} do not. The
 * prefixes are {@code api}, {@code ssl}, {@code tls}, {@code private}, {@code access}, {@code secret},
 * {@code auth}, {@code encryption}, {@code signing}, {@code master}, {@code hmac}, {@code pass},
 * {@code session}, {@code client}, {@code license}, {@code aes}, {@code rsa} and {@code jwt}. A name whose
 * last component is a source-file extension ({@code java}, {@code kt}, {@code scala}, {@code groovy}) and that
 * is followed by {@code :} and a digit is a stack-trace position, not a label.
 *
 * <p>A label is a sensitive name followed, after optional blanks (space and tab), by {@code =} or
 * {@code :}. The name may be wrapped in a matching pair of quotes, as in JSON ({@code "password": "x"}).
 * What is withheld depends on the value and on the context:
 *
 * <table class="striped">
 *   <caption>Value withheld per context</caption>
 *   <thead><tr><th>Context</th><th>Withheld</th></tr></thead>
 *   <tbody>
 *   <tr><td>Quoted value ({@code '} or {@code "} after the separator), any sensitive name</td>
 *       <td>The text up to the first closing quote of the same kind that is not escaped. A backslash escapes
 *       the next character, and a doubled quote ({@code 'it''s'}) is one quote inside the value. A value
 *       that is not closed runs to the end of the message. The quotes stay.</td></tr>
 *   <tr><td>Unquoted value of a password name in a URL-query context</td>
 *       <td>Up to the next {@code &}, {@code ;}, quote, {@code )} or white space. A URL-query context is a
 *       label whose first character is immediately preceded by {@code ?}, {@code &} or {@code ;}, so
 *       {@code ?password=x&ssl=true} keeps {@code ssl=true}. A comma does not end the value.</td></tr>
 *   <tr><td>Unquoted value of a password name in any other context</td>
 *       <td>Up to the end of the line ({@code \n}, {@code \r}, U+0085, U+2028, U+2029). A password may hold
 *       blanks, commas and {@code &}, and nothing in the text says where it ends, so the whole rest of the
 *       line is withheld: {@code password=my secret pass} and {@code password=a,b} are withheld whole, and so
 *       is what follows on that line ({@code host=h password=p dbname=d} loses {@code dbname=d}).</td></tr>
 *   <tr><td>Unquoted value, name wrapped in quotes (JSON-like), any sensitive name</td>
 *       <td>Up to the next {@code ,}, the closing brace, {@code ]}, {@code )}, {@code &}, {@code ;}, quote or white
 *       space: the grammar of the surrounding structure ends it.</td></tr>
 *   <tr><td>Unquoted value of a sensitive name that is not a password name ({@code secret}, {@code token},
 *       {@code credential}, a key name), otherwise</td>
 *       <td>Up to the next {@code &}, {@code ;}, {@code ,}, quote, {@code )} or white space. A value with
 *       such a character in it leaks its tail: this is best effort.</td></tr>
 *   <tr><td>{@code Authorization} and {@code Proxy-Authorization} lines (the whole name, any case, followed
 *       by {@code :})</td>
 *       <td>Everything after the scheme up to the end of the line: {@code Authorization: Bearer <withheld>}.
 *       The scheme is a public word that tells an operator what kind of credential was refused; the
 *       credential is whatever follows it. A value of one word has no scheme and is withheld whole.</td></tr>
 *   <tr><td>{@code Cookie} and {@code Set-Cookie} lines (same form)</td>
 *       <td>Everything after the colon up to the end of the line: a cookie's name, value and attributes
 *       together name a session, and none of it is needed in this launcher's log. A quoted value follows the
 *       quoted rule instead. The {@code =} form of these names is not a header and is not withheld.</td></tr>
 *   <tr><td>Command-line flag: {@code --} followed by a sensitive name, then blanks, then a word that does not
 *       start with {@code -}</td>
 *       <td>The next word (up to white space; a quoted word follows the quoted rule). A flag that names a
 *       secret is followed by it in every command-line grammar. The short form {@code -p<value>} or
 *       {@code -p <value>} is ambiguous (port, path, profile) and is not withheld.</td></tr>
 *   </tbody>
 * </table>
 *
 * <p>Out of scope, so not withheld: a secret that is not configured and not behind one of the shapes above
 * (for example {@code password is hunter2}), a name that merely resembles a sensitive word, case variants of
 * a configured secret, a configured secret split by a line break.
 *
 * <h2>Invariants</h2>
 * <ul>
 *   <li>It never throws; when it cannot finish, or a bound is exceeded, it returns a fixed text that holds
 *       none of the message.</li>
 *   <li>Its time and memory are linear in the length of the message plus the length of the secrets, for the
 *       bounded number of secrets: every scan is a single left-to-right pass with no backtracking.</li>
 *   <li>Every occurrence of a configured secret of at least {@link #MINIMUM_SECRET_LENGTH} characters in the
 *       input, in the forms above, is withheld, whatever the order of the secrets and whatever the structure
 *       stage decided.</li>
 *   <li>A secret shorter than {@link #MINIMUM_SECRET_LENGTH} is not replaced where it merely occurs: a one-
 *       or two-character secret would blank every such character of every message, and the result would no
 *       longer say what failed. It is still withheld wherever it is the value of a label or the password of an
 *       authority, because the structure stage does not depend on the secret.</li>
 *   <li>Text outside a withheld range is not altered.</li>
 * </ul>
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

    /** The most distinct configured secrets (of at least the minimum length) one call accepts. */
    static final int MAXIMUM_SECRETS = 8;

    /** Parts of a name that make it a password name, matched in any case. */
    private static final List<String> PASSWORD_WORDS = List.of("password", "passwd", "pwd", "passphrase");

    /** Further parts of a name that make it sensitive, matched in any case. */
    private static final List<String> OTHER_WORDS = List.of("secret", "token", "credential");

    /** What may precede {@code key} in the last component of a name for it to be a key word. */
    private static final Set<String> KEY_PREFIXES = Set.of("api", "ssl", "tls", "private", "access", "secret",
            "auth", "encryption", "signing", "master", "hmac", "pass", "session", "client", "license", "aes", "rsa",
            "jwt");

    private static final List<String> CREDENTIAL_HEADERS = List.of("authorization", "proxy-authorization");

    private static final List<String> COOKIE_HEADERS = List.of("cookie", "set-cookie");

    private static final List<String> SOURCE_EXTENSIONS = List.of(".java", ".kt", ".scala", ".groovy");

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
     * @return the message to log; a placeholder when there was none, and the fixed text
     *         {@code (message withheld)} when a cap was exceeded or the message could not be processed
     */
    static String of(String message, String... secrets) {
        if (message == null || message.isBlank()) {
            return "(no message)";
        }
        try {
            Set<String> configured = configuredSecrets(secrets);
            if (configured == null) {
                return UNREADABLE;
            }
            int n = message.length();
            boolean[] byConfiguredSecret = new boolean[n];
            if (!configured.isEmpty()) {
                markConfiguredSecrets(message, configured, byConfiguredSecret);
            }
            boolean[] withheld = byConfiguredSecret.clone();
            BitSet empty = new BitSet();
            markAuthorityPasswords(message, withheld, empty);
            markLabelledValues(message, withheld, empty);
            return render(message, withheld, empty);
        } catch (RuntimeException e) {
            return UNREADABLE;
        }
    }

    // ---- rendering -------------------------------------------------------------------------------------

    /**
     * Writes the message with each maximal run of withheld characters, and each empty withheld value that
     * does not touch such a run, replaced by one placeholder.
     */
    private static String render(String text, boolean[] withheld, BitSet empty) {
        int n = text.length();
        StringBuilder out = new StringBuilder(n);
        boolean inside = false;
        for (int i = 0; i <= n; i++) {
            if (i < n && withheld[i]) {
                if (!inside) {
                    out.append(WITHHELD);
                    inside = true;
                }
                continue;
            }
            if (!inside && empty.get(i)) {
                out.append(WITHHELD);
            }
            inside = false;
            if (i < n) {
                out.append(text.charAt(i));
            }
        }
        return out.toString();
    }

    private static void mark(boolean[] withheld, BitSet empty, int from, int to) {
        if (from >= to) {
            empty.set(from);
            return;
        }
        for (int i = from; i < to; i++) {
            withheld[i] = true;
        }
    }

    // ---- stage 1: configured secrets -------------------------------------------------------------------

    /**
     * The distinct secrets that are withheld wherever they occur, or {@code null} when a cap is exceeded.
     */
    private static Set<String> configuredSecrets(String[] secrets) {
        Set<String> eligible = new LinkedHashSet<>();
        if (secrets == null) {
            return eligible;
        }
        for (String secret : secrets) {
            if (secret != null && secret.length() >= MINIMUM_SECRET_LENGTH && eligible.add(secret)) {
                if (eligible.size() > MAXIMUM_SECRETS) {
                    return null;
                }
            }
        }
        return eligible;
    }

    private static Set<String> base64Forms(String secret) {
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        Set<String> forms = new LinkedHashSet<>();
        forms.add(Base64.getEncoder().encodeToString(bytes));
        forms.add(Base64.getEncoder().withoutPadding().encodeToString(bytes));
        forms.add(Base64.getUrlEncoder().encodeToString(bytes));
        forms.add(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
        return forms;
    }

    private static void markConfiguredSecrets(String text, Set<String> secrets, boolean[] byConfiguredSecret) {
        int length = text.length();
        int[] delta = new int[length + 1];
        DecodedView view = text.indexOf('%') >= 0 || text.indexOf('+') >= 0 ? DecodedView.of(text) : null;
        for (String secret : secrets) {
            markOccurrences(text, secret, delta);
            for (String form : base64Forms(secret)) {
                markOccurrences(text, form, delta);
            }
            if (view != null) {
                view.markOccurrences(secret.getBytes(StandardCharsets.UTF_8), delta);
            }
        }
        int covered = 0;
        for (int i = 0; i < length; i++) {
            covered += delta[i];
            byConfiguredSecret[i] = covered > 0;
        }
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

    /**
     * The message as a sequence of bytes with its percent-escapes decoded, and for each byte the range of the
     * original text that spelled it. A literal character contributes the bytes of its UTF-8 encoding, each
     * mapped to that character's range; {@code %XX} with two hexadecimal digits contributes one byte mapped to
     * those three characters; a {@code %} that does not start such an escape is a literal. A surrogate that is
     * not part of a pair contributes {@code ?}, as {@link String#getBytes} does.
     */
    private static final class DecodedView {
        /** How many steps of confirming candidates one search may take per byte of message and secret. */
        private static final int CONFIRMATION_FACTOR = 16;

        private byte[] bytes;
        private int[] from;
        private int[] to;
        private final BitSet plus = new BitSet();
        private int size;

        private DecodedView(int capacity) {
            bytes = new byte[capacity];
            from = new int[capacity];
            to = new int[capacity];
        }

        static DecodedView of(String text) {
            int n = text.length();
            DecodedView view = new DecodedView(n + 16);
            int i = 0;
            while (i < n) {
                char c = text.charAt(i);
                if (c == '%' && i + 2 < n && hex(text.charAt(i + 1)) >= 0 && hex(text.charAt(i + 2)) >= 0) {
                    view.add((byte) (hex(text.charAt(i + 1)) << 4 | hex(text.charAt(i + 2))), i, i + 3, false);
                    i += 3;
                    continue;
                }
                int cp = text.codePointAt(i);
                int width = Character.charCount(cp);
                if (cp >= Character.MIN_SURROGATE && cp <= Character.MAX_SURROGATE) {
                    view.add((byte) '?', i, i + width, false);
                } else if (cp < 0x80) {
                    view.add((byte) cp, i, i + width, cp == '+');
                } else {
                    for (byte b : new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8)) {
                        view.add(b, i, i + width, false);
                    }
                }
                i += width;
            }
            return view;
        }

        private void add(byte value, int origin, int originEnd, boolean isPlus) {
            if (size == bytes.length) {
                int grown = Math.max(16, size * 2);
                bytes = java.util.Arrays.copyOf(bytes, grown);
                from = java.util.Arrays.copyOf(from, grown);
                to = java.util.Arrays.copyOf(to, grown);
            }
            bytes[size] = value;
            from[size] = origin;
            to[size] = originEnd;
            if (isPlus) {
                plus.set(size);
            }
            size++;
        }

        /**
         * The class of a byte for the search: a space and a {@code +} are one symbol, every other byte is its
         * own. Applied to the message and to the secret alike, it is an equivalence, so equality of classes
         * is the relation a Knuth-Morris-Pratt search needs.
         */
        private static byte folded(byte value) {
            return value == ' ' ? (byte) '+' : value;
        }

        /**
         * Whether the message byte at {@code index} may stand for the secret byte {@code expected}, which is a
         * space or a {@code +}. A space in the secret is written as a space, a {@code %20}, or a literal
         * {@code +}; a {@code +} in the secret is written as a literal {@code +} or {@code %2B}, and never as a
         * space.
         */
        private boolean stands(int index, byte expected) {
            return expected == ' ' ? bytes[index] == ' ' || plus.get(index) : bytes[index] == '+';
        }

        /**
         * Adds +1 at the start and -1 after the end of every occurrence of {@code pattern} in the decoded
         * message, mapped back to the original text.
         *
         * <p>The relation between a message byte and a secret byte is not an equivalence: a literal
         * {@code +} in the message is compatible with a space in the secret and with a {@code +} in the
         * secret, while a space is compatible only with a space and a {@code %2B} only with a {@code +}.
         * The search therefore runs in two steps. The first is a Knuth-Morris-Pratt search over
         * {@link #folded folded} symbols, in which the compatible pairs are all equal; it finds a superset
         * of the occurrences, and being a search over an equivalence it is correct, and linear in
         * {@code size + pattern.length}. The second confirms each candidate against the exact relation at
         * the secret's spaces and pluses, the only positions where the two differ: every other secret byte
         * has already been compared for equality.
         *
         * <p>A confirmation costs at most the number of spaces and pluses in the secret, and ends at the
         * first position that disagrees. The cost of all confirmations is bounded by
         * {@value #CONFIRMATION_FACTOR} times the sum of the lengths of the message and the secret; an input
         * that would exceed it ends the call in the fixed text, so that the function stays linear and fails
         * closed. Ordinary input does not come near it: a candidate needs the message to hold, at the secret's
         * spaces and pluses, exactly the spaces and pluses of the secret.
         */
        void markOccurrences(byte[] pattern, int[] delta) {
            int m = pattern.length;
            byte[] folded = new byte[m];
            int separators = 0;
            for (int i = 0; i < m; i++) {
                folded[i] = folded(pattern[i]);
                if (pattern[i] == ' ' || pattern[i] == '+') {
                    separators++;
                }
            }
            int[] separatorAt = new int[separators];
            for (int i = 0, next = 0; i < m; i++) {
                if (pattern[i] == ' ' || pattern[i] == '+') {
                    separatorAt[next++] = i;
                }
            }
            int[] fallback = new int[m];
            for (int i = 1, k = 0; i < m; i++) {
                while (k > 0 && folded[i] != folded[k]) {
                    k = fallback[k - 1];
                }
                if (folded[i] == folded[k]) {
                    k++;
                }
                fallback[i] = k;
            }
            long budget = CONFIRMATION_FACTOR * ((long) size + m);
            for (int i = 0, k = 0; i < size; i++) {
                byte symbol = folded(bytes[i]);
                while (k > 0 && symbol != folded[k]) {
                    k = fallback[k - 1];
                }
                if (symbol == folded[k]) {
                    k++;
                }
                if (k == m) {
                    int start = i - m + 1;
                    boolean exact = true;
                    for (int j = 0; j < separators && exact; j++) {
                        budget--;
                        exact = stands(start + separatorAt[j], pattern[separatorAt[j]]);
                    }
                    if (budget < 0) {
                        throw new ConfirmationBudgetExceeded();
                    }
                    if (exact) {
                        delta[from[start]]++;
                        delta[to[i]]--;
                    }
                    k = fallback[k - 1];
                }
            }
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
    }

    /** The search for a secret would cost more than its bound; the call ends in the fixed text. */
    private static final class ConfirmationBudgetExceeded extends RuntimeException {
        private static final long serialVersionUID = 1L;

        ConfirmationBudgetExceeded() {
            super(null, null, false, false);
        }
    }

    // ---- stage 2: structure ----------------------------------------------------------------------------

    /** {@code ://user:password@}: the password is whatever lies between the first colon and the {@code @}. */
    private static void markAuthorityPasswords(String text, boolean[] withheld, BitSet empty) {
        int n = text.length();
        int i = 0;
        while (i < n) {
            int scheme = text.indexOf("://", i);
            if (scheme < 0) {
                return;
            }
            int user = scheme + 3;
            int colon = user;
            while (colon < n && !isUserInfoStop(text, colon, withheld) && !isColon(text, colon, withheld)) {
                colon++;
            }
            boolean hasColon = colon < n && isColon(text, colon, withheld);
            int at = colon + 1;
            if (hasColon) {
                // The password may itself hold ':'; it ends at the first '@' reached before a delimiter.
                while (at < n && !isUserInfoStop(text, at, withheld)) {
                    at++;
                }
            }
            if (hasColon && at < n && text.charAt(at) == '@' && !withheld[at]) {
                mark(withheld, empty, colon + 1, at);
                i = at;
            } else {
                i = user;
            }
        }
    }

    private static boolean isColon(String text, int index, boolean[] withheld) {
        return text.charAt(index) == ':' && !withheld[index];
    }

    private static boolean isUserInfoStop(String text, int index, boolean[] withheld) {
        char c = text.charAt(index);
        return !withheld[index] && (c == '/' || c == '@' || c == '?' || c == '#' || Character.isWhitespace(c));
    }

    private enum Kind { NONE, CREDENTIAL_HEADER, COOKIE_HEADER, PASSWORD, OTHER }

    private enum Ends { LINE, URL_QUERY, STRUCTURE, DELIMITER }

    /**
     * A withheld character is not a name character, exactly as the placeholder that replaces it is not, so
     * that the names found do not depend on whether an earlier stage's placeholder is already in the text.
     */
    private static void markLabelledValues(String text, boolean[] withheld, BitSet empty) {
        int n = text.length();
        int i = 0;
        while (i < n) {
            if (withheld[i] || !isNameChar(text.charAt(i))) {
                i++;
                continue;
            }
            int end = i;
            while (end < n && !withheld[end] && isNameChar(text.charAt(end))) {
                end++;
            }
            i = labelAt(text, i, end, withheld, empty);
        }
    }

    /** Handles the name {@code [from, end)}; returns the index at which scanning continues, at least {@code end}. */
    private static int labelAt(String text, int from, int end, boolean[] withheld, BitSet empty) {
        int n = text.length();
        Kind kind = classify(text, from, end);
        if (kind == Kind.NONE) {
            return end;
        }
        char opener = from > 0 && !withheld[from - 1] ? text.charAt(from - 1) : 0;
        boolean quotedName = isQuote(opener) && end < n && !withheld[end] && text.charAt(end) == opener;
        int afterName = quotedName ? end + 1 : end;
        int separator = skipBlanks(text, afterName, withheld);
        if (separator >= n || withheld[separator]) {
            return end;
        }
        char sign = text.charAt(separator);
        if (sign != '=' && sign != ':') {
            return !isHeader(kind) && !quotedName && separator > afterName && isFlag(text, from, end, opener)
                    ? withholdFlagValue(text, separator, withheld, empty) : end;
        }
        if (isHeader(kind) && sign != ':') {
            return end;
        }
        if (sign == ':' && isSourcePosition(text, from, end, separator, withheld)) {
            return end;
        }
        int value = skipBlanks(text, separator + 1, withheld);
        if (value >= n) {
            return n;
        }
        if (!withheld[value] && isQuote(text.charAt(value))) {
            return withholdQuoted(text, value, withheld, empty);
        }
        if (kind == Kind.CREDENTIAL_HEADER) {
            value = afterScheme(text, value, withheld);
        }
        Ends ends;
        if (isHeader(kind)) {
            ends = Ends.LINE;
        } else if (quotedName) {
            ends = Ends.STRUCTURE;
        } else if (kind == Kind.PASSWORD) {
            ends = isQueryOpener(opener) ? Ends.URL_QUERY : Ends.LINE;
        } else {
            ends = Ends.DELIMITER;
        }
        int stop = value;
        while (stop < n && (withheld[stop] || !endsValue(text.charAt(stop), ends))) {
            stop++;
        }
        if (stop > value) {
            mark(withheld, empty, value, stop);
        }
        return stop;
    }

    private static boolean isHeader(Kind kind) {
        return kind == Kind.CREDENTIAL_HEADER || kind == Kind.COOKIE_HEADER;
    }

    /**
     * Where the credentials of an {@code Authorization} value begin: after the scheme and the blanks that
     * follow it, when there are credentials on the same line; otherwise the start of the value, because a lone
     * word is itself the credential.
     */
    private static int afterScheme(String text, int value, boolean[] withheld) {
        int n = text.length();
        int word = value;
        while (word < n && (withheld[word] || !Character.isWhitespace(text.charAt(word)))) {
            word++;
        }
        int credentials = skipBlanks(text, word, withheld);
        return credentials > word && credentials < n
                && (withheld[credentials] || !endsValue(text.charAt(credentials), Ends.LINE))
                ? credentials : value;
    }

    /** The value after a flag such as {@code --password}: the next word, or the next quoted text. */
    private static int withholdFlagValue(String text, int start, boolean[] withheld, BitSet empty) {
        int n = text.length();
        char first = text.charAt(start);
        if (!withheld[start] && (first == '-' || Character.isWhitespace(first))) {
            return start;
        }
        if (!withheld[start] && isQuote(first)) {
            return withholdQuoted(text, start, withheld, empty);
        }
        int stop = start;
        while (stop < n && (withheld[stop] || !Character.isWhitespace(text.charAt(stop)))) {
            stop++;
        }
        mark(withheld, empty, start, stop);
        return stop;
    }

    /**
     * Withholds the text inside the quotes opened at {@code open}; returns the index after the closing quote,
     * or the end of the message when it is not closed. A character already withheld never closes the value.
     */
    private static int withholdQuoted(String text, int open, boolean[] withheld, BitSet empty) {
        int n = text.length();
        char quote = text.charAt(open);
        int p = open + 1;
        while (p < n) {
            char c = text.charAt(p);
            if (withheld[p]) {
                p++;
            } else if (c == '\\') {
                p += 2;
            } else if (c == quote) {
                if (p + 1 < n && text.charAt(p + 1) == quote && !withheld[p + 1]) {
                    p += 2;
                } else {
                    mark(withheld, empty, open + 1, p);
                    return p + 1;
                }
            } else {
                p++;
            }
        }
        mark(withheld, empty, open + 1, n);
        return n;
    }

    private static boolean endsValue(char c, Ends ends) {
        return switch (ends) {
            case LINE -> c == '\n' || c == '\r' || c == '\u0085' || c == ' ' || c == ' ';
            case URL_QUERY -> c == '&' || c == ';' || c == '\'' || c == '"' || c == ')' || Character.isWhitespace(c);
            case STRUCTURE -> c == ',' || c == '}' || c == ']' || c == '&' || c == ';' || c == '\'' || c == '"'
                    || c == ')' || Character.isWhitespace(c);
            case DELIMITER -> c == '&' || c == ';' || c == ',' || c == '\'' || c == '"' || c == ')'
                    || Character.isWhitespace(c);
        };
    }

    private static boolean isQueryOpener(char c) {
        return c == '?' || c == '&' || c == ';';
    }

    private static boolean isQuote(char c) {
        return c == '\'' || c == '"';
    }

    private static int skipBlanks(String text, int from, boolean[] withheld) {
        int i = from;
        while (i < text.length() && !withheld[i] && (text.charAt(i) == ' ' || text.charAt(i) == '\t')) {
            i++;
        }
        return i;
    }

    private static boolean isNameChar(char c) {
        return c == '_' || c == '.' || c == '-' || Character.isLetterOrDigit(c);
    }

    private static boolean isComponentSeparator(char c) {
        return c == '_' || c == '.' || c == '-';
    }

    /** A name that starts with two dashes, at the start of a word. */
    private static boolean isFlag(String text, int from, int end, char before) {
        return end - from > 2 && text.charAt(from) == '-' && text.charAt(from + 1) == '-' && text.charAt(from + 2) != '-'
                && (from == 0 || Character.isWhitespace(before));
    }

    /** {@code Name.java:42}: the position in a stack trace, whatever the file is called. */
    private static boolean isSourcePosition(String text, int from, int end, int colon, boolean[] withheld) {
        if (colon + 1 >= text.length() || withheld[colon + 1] || !Character.isDigit(text.charAt(colon + 1))) {
            return false;
        }
        for (String extension : SOURCE_EXTENSIONS) {
            if (end - from > extension.length()
                    && text.regionMatches(true, end - extension.length(), extension, 0, extension.length())) {
                return true;
            }
        }
        return false;
    }

    private static Kind classify(String text, int from, int to) {
        int length = to - from;
        for (String header : CREDENTIAL_HEADERS) {
            if (header.length() == length && text.regionMatches(true, from, header, 0, length)) {
                return Kind.CREDENTIAL_HEADER;
            }
        }
        for (String header : COOKIE_HEADERS) {
            if (header.length() == length && text.regionMatches(true, from, header, 0, length)) {
                return Kind.COOKIE_HEADER;
            }
        }
        if (containsWord(text, from, to, PASSWORD_WORDS)) {
            return Kind.PASSWORD;
        }
        if (containsWord(text, from, to, OTHER_WORDS) || endsInKeyWord(text, from, to)) {
            return Kind.OTHER;
        }
        return Kind.NONE;
    }

    private static boolean containsWord(String text, int from, int to, List<String> words) {
        for (String word : words) {
            for (int p = from; p + word.length() <= to; p++) {
                if (text.regionMatches(true, p, word, 0, word.length())) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Whether the last component of the name is {@code key}, or a known prefix followed by {@code key}. */
    private static boolean endsInKeyWord(String text, int from, int to) {
        int component = to;
        while (component > from && !isComponentSeparator(text.charAt(component - 1))) {
            component--;
        }
        if (component == to) {
            return false;
        }
        int word = to - 1;
        while (word > component) {
            char c = text.charAt(word);
            char before = text.charAt(word - 1);
            if (Character.isUpperCase(c) && (Character.isLowerCase(before) || Character.isDigit(before))) {
                break;
            }
            if (Character.isUpperCase(c) && Character.isUpperCase(before) && word + 1 < to
                    && Character.isLowerCase(text.charAt(word + 1))) {
                break;
            }
            word--;
        }
        int length = to - word;
        if (length < 3 || !text.regionMatches(true, to - 3, "key", 0, 3)) {
            return false;
        }
        if (length == 3) {
            return true;
        }
        return KEY_PREFIXES.contains(text.substring(word, to - 3).toLowerCase(Locale.ROOT));
    }
}
