package eu.exeris.sku.identity.launcher;

import java.util.regex.Pattern;

/**
 * Makes a message the kernel or a driver produced safe to write to the log. The kernel's text is what an
 * operator needs, for instance the licence gate's code and reason, but a connection failure can quote the
 * JDBC URL it was given, and that URL is operator input that may carry credentials.
 *
 * <p>Three things are withheld: the database password wherever it appears, the password part of
 * {@code user:password@host} authority, and the value of a parameter whose name says it is a secret
 * ({@code password=}, {@code sslpassword=}, {@code token=} and the like). Nothing else is altered.
 */
final class LogRedaction {

    /** What replaces a withheld value. */
    static final String WITHHELD = "<withheld>";

    private static final Pattern AUTHORITY_PASSWORD = Pattern.compile("(://[^/\\s:@?#]*):[^/\\s@?#]*@");
    private static final Pattern SECRET_PARAMETER = Pattern.compile(
            "(?i)(\\b(?:ssl)?(?:key)?(?:password|passwd|pwd)|\\bsecret|\\btoken)(\\s*[=:]\\s*)[^&;\\s,'\")]+");

    private LogRedaction() {
    }

    /**
     * Returns the message with every credential withheld.
     *
     * @param message the message of an exception; may be {@code null}
     * @param secrets values that must never appear, such as the database password; {@code null} and empty
     *                values are ignored
     * @return the message to log; a placeholder when there was none
     */
    static String of(String message, String... secrets) {
        if (message == null || message.isBlank()) {
            return "(no message)";
        }
        String safe = AUTHORITY_PASSWORD.matcher(message).replaceAll("$1:" + WITHHELD + "@");
        safe = SECRET_PARAMETER.matcher(safe).replaceAll("$1$2" + WITHHELD);
        for (String secret : secrets) {
            if (secret != null && !secret.isEmpty()) {
                safe = safe.replace(secret, WITHHELD);
            }
        }
        return safe;
    }
}
