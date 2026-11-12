package eu.exeris.sku.identity.launcher;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
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
 * percent-escapes. No fragment is accepted. A query parameter is accepted only when it is on the list of
 * {@link #PARAMETERS} and its value has that parameter's grammar; names are matched exactly and in case as
 * the driver spells them, with no percent-escape, and a name that appears twice is refused. Everything else
 * is refused before the driver is called, because the driver quotes the value of a parameter it cannot read
 * in its own log records. The list holds what a deployment tunes (TLS mode, timeouts, host selection, a few
 * session settings) and nothing that names a class, a file or a socket, carries free text to the server,
 * changes logging, or is a credential or an alias of one.
 */
final class JdbcUrl {

    private static final String PREFIX = "jdbc:postgresql://";
    private static final Pattern NAME_HOST = Pattern.compile("[A-Za-z0-9._-]+");
    private static final Pattern IPV6_HOST = Pattern.compile("\\[[0-9A-Fa-f:.]+]");
    private static final Pattern PORT = Pattern.compile("[0-9]{1,5}");
    private static final Pattern DATABASE = Pattern.compile("[A-Za-z0-9._~%-]+");
    private static final Pattern BOOLEAN = Pattern.compile("true|false");
    private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z0-9_]+");
    private static final Pattern APPLICATION_NAME = Pattern.compile("[A-Za-z0-9._-]{1,63}");
    private static final Pattern VERSION = Pattern.compile("[0-9]{1,6}(\\.[0-9]{1,6}){0,2}");

    /** The parameters of the URL's query and the value each accepts; the maximum length of a list is 255. */
    private static final Map<String, Predicate<String>> PARAMETERS = parameters();

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

    private static Map<String, Predicate<String>> parameters() {
        Predicate<String> seconds = number(86_400);
        return Map.ofEntries(
                Map.entry("ssl", BOOLEAN.asMatchPredicate()),
                Map.entry("sslmode", words("disable", "allow", "prefer", "require", "verify-ca", "verify-full")),
                Map.entry("connectTimeout", seconds),
                Map.entry("socketTimeout", seconds),
                Map.entry("loginTimeout", seconds),
                Map.entry("cancelSignalTimeout", seconds),
                Map.entry("hostRecheckSeconds", seconds),
                Map.entry("tcpKeepAlive", BOOLEAN.asMatchPredicate()),
                Map.entry("prepareThreshold", number(10_000)),
                Map.entry("defaultRowFetchSize", number(1_000_000)),
                Map.entry("targetServerType", words("any", "primary", "master", "slave", "secondary",
                        "preferSlave", "preferSecondary", "preferPrimary")),
                Map.entry("loadBalanceHosts", BOOLEAN.asMatchPredicate()),
                Map.entry("reWriteBatchedInserts", BOOLEAN.asMatchPredicate()),
                Map.entry("ApplicationName", APPLICATION_NAME.asMatchPredicate()),
                Map.entry("currentSchema", JdbcUrl::identifierList),
                Map.entry("stringtype", words("unspecified", "varchar")),
                Map.entry("assumeMinServerVersion", VERSION.asMatchPredicate()),
                Map.entry("gssEncMode", words("disable", "allow", "prefer", "require")),
                Map.entry("channelBinding", words("disable", "prefer", "require")));
    }

    private static Predicate<String> words(String... accepted) {
        Set<String> set = Set.of(accepted);
        return set::contains;
    }

    /** A decimal integer without sign or leading plus, from 0 to the maximum. */
    private static Predicate<String> number(int maximum) {
        return value -> value.length() >= 1 && value.length() <= 9 && value.chars().allMatch(c -> c >= '0' && c <= '9')
                && Integer.parseInt(value) <= maximum;
    }

    private static boolean parameters(String query) {
        if (query.isEmpty()) {
            return false;
        }
        Set<String> seen = new HashSet<>();
        for (String parameter : query.split("&", -1)) {
            int equals = parameter.indexOf('=');
            if (equals < 0) {
                return false;
            }
            String name = parameter.substring(0, equals);
            Predicate<String> grammar = PARAMETERS.get(name);
            if (grammar == null || !seen.add(name) || !grammar.test(parameter.substring(equals + 1))) {
                return false;
            }
        }
        return true;
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

    /** One or more identifiers separated by commas, at most 255 characters in all; no empty identifier. */
    private static boolean identifierList(String value) {
        if (value.length() > 255) {
            return false;
        }
        for (String identifier : value.split(",", -1)) {
            if (!IDENTIFIER.matcher(identifier).matches()) {
                return false;
            }
        }
        return true;
    }
}
