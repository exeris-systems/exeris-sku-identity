package eu.exeris.sku.identity.launcher;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * The only shape of JDBC URL the launcher hands to the PostgreSQL driver.
 *
 * <p>The driver reports a URL it cannot parse through the logging framework, before any exception exists,
 * and the text it writes quotes part of the URL. A URL that carries a credential in its authority or its
 * query would therefore reach the output from the driver itself. So the launcher parses the URL first and
 * the driver sees nothing else:
 * <pre>
 * jdbc:postgresql://host[:port][,host[:port]...]/database[?name=value[&amp;name=value...]]
 * </pre>
 * A host is a name, an IPv4 address or a bracketed IPv6 address; a port is a number from 1 to 65535. The
 * authority holds no user-info: an {@code @} anywhere in it is a refusal, because credentials belong in the
 * user and password settings. The database name is made of letters, digits and {@code . _ ~ -}, with
 * percent-escapes. No fragment is accepted. A query parameter must have a plain name and a well-formed
 * value and must not name the user or a password: {@code user}, {@code password}, {@code sslpassword} or any
 * name that contains {@code password}, {@code passwd}, {@code pwd} or {@code passphrase}, in any case and in
 * any percent-escaped spelling.
 */
final class JdbcUrl {

    private static final String PREFIX = "jdbc:postgresql://";
    private static final Pattern NAME_HOST = Pattern.compile("[A-Za-z0-9._-]+");
    private static final Pattern IPV6_HOST = Pattern.compile("\\[[0-9A-Fa-f:.]+]");
    private static final Pattern PORT = Pattern.compile("[0-9]{1,5}");
    private static final Pattern DATABASE = Pattern.compile("[A-Za-z0-9._~%-]+");
    private static final Pattern PARAMETER = Pattern.compile("[A-Za-z][A-Za-z0-9_.-]*");

    private JdbcUrl() {
    }

    /**
     * Whether the URL has the accepted shape.
     *
     * @param url the URL as configured; may be null
     * @return true when the URL may be handed to the driver; never throws
     */
    static boolean acceptable(String url) {
        if (url == null || !url.startsWith(PREFIX)) {
            return false;
        }
        String rest = url.substring(PREFIX.length());
        int end = indexOfAny(rest, "/?#");
        if (end <= 0 || rest.charAt(end) != '/') {
            return false;
        }
        if (!hosts(rest.substring(0, end))) {
            return false;
        }
        int query = rest.indexOf('?', end);
        String database = rest.substring(end + 1, query < 0 ? rest.length() : query);
        if (!DATABASE.matcher(database).matches() || !wellFormedEscapes(database)) {
            return false;
        }
        if (rest.indexOf('#') >= 0) {
            return false;
        }
        return query < 0 || parameters(rest.substring(query + 1));
    }

    private static boolean hosts(String authority) {
        if (authority.indexOf('@') >= 0) {
            return false;
        }
        for (String endpoint : authority.split(",", -1)) {
            String host = endpoint;
            String port = null;
            boolean bracketed = endpoint.startsWith("[");
            int close = bracketed ? endpoint.indexOf(']') : -1;
            if (bracketed && close < 0) {
                return false;
            }
            int separator = bracketed ? close + 1 : endpoint.indexOf(':');
            if (separator >= 0 && separator < endpoint.length()) {
                if (endpoint.charAt(separator) != ':') {
                    return false;
                }
                host = endpoint.substring(0, separator);
                port = endpoint.substring(separator + 1);
            }
            boolean hostOk = bracketed ? IPV6_HOST.matcher(host).matches() : NAME_HOST.matcher(host).matches();
            if (!hostOk) {
                return false;
            }
            if (port != null && !(PORT.matcher(port).matches() && Integer.parseInt(port) >= 1
                    && Integer.parseInt(port) <= 65_535)) {
                return false;
            }
        }
        return true;
    }

    private static boolean parameters(String query) {
        if (query.isEmpty()) {
            return false;
        }
        for (String parameter : query.split("&", -1)) {
            int equals = parameter.indexOf('=');
            String name = equals < 0 ? parameter : parameter.substring(0, equals);
            String value = equals < 0 ? "" : parameter.substring(equals + 1);
            String decoded = decode(name);
            if (decoded == null || !PARAMETER.matcher(decoded).matches() || namesCredential(decoded)
                    || !wellFormedEscapes(value) || containsBlankOrControl(value)) {
                return false;
            }
        }
        return true;
    }

    private static boolean namesCredential(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        return lower.equals("user") || lower.contains("password") || lower.contains("passwd")
                || lower.contains("pwd") || lower.contains("passphrase");
    }

    private static boolean containsBlankOrControl(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c <= ' ' || c == 0x7f) {
                return true;
            }
        }
        return false;
    }

    /** The name with its percent-escapes of ASCII characters decoded; null when an escape is malformed. */
    private static String decode(String name) {
        StringBuilder out = new StringBuilder(name.length());
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c != '%') {
                out.append(c);
                continue;
            }
            if (i + 2 >= name.length()) {
                return null;
            }
            int high = Character.digit(name.charAt(i + 1), 16);
            int low = Character.digit(name.charAt(i + 2), 16);
            if (high < 0 || low < 0 || high > 7) {
                return null;
            }
            out.append((char) (high * 16 + low));
            i += 2;
        }
        return out.toString();
    }

    private static boolean wellFormedEscapes(String text) {
        for (int i = 0; i < text.length(); i++) {
            if (text.charAt(i) == '%') {
                if (i + 2 >= text.length()) {
                    return false;
                }
                if (Character.digit(text.charAt(i + 1), 16) < 0 || Character.digit(text.charAt(i + 2), 16) < 0) {
                    return false;
                }
                i += 2;
            }
        }
        return true;
    }

    private static int indexOfAny(String text, String characters) {
        for (int i = 0; i < text.length(); i++) {
            if (characters.indexOf(text.charAt(i)) >= 0) {
                return i;
            }
        }
        return -1;
    }
}
