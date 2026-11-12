package eu.exeris.sku.identity.launcher;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The only JDBC URL the launcher hands to the driver is the one the configuration reference describes
 * ("The JDBC URL rule"): {@code jdbc:postgresql://} hosts {@code /} database and an optional query, with no
 * user-info, no fragment and no parameter that names the user or a password.
 *
 * <p>The tables state the rule from the reference, not from the implementation; the property at the end
 * restates the security consequence with a parser of its own.
 */
@DisplayName("JdbcUrl: the shape of a database URL the driver may see")
class JdbcUrlTest {

    private static final String BASE = "jdbc:postgresql://host:5432/identity";

    @Test
    @DisplayName("Accepted: a host, a host and port, several hosts, an IPv6 host, a database name with - _ . ~ and escapes, and plain parameters")
    void accepted() {
        List<String> urls = List.of(
                "jdbc:postgresql://host/db",
                "jdbc:postgresql://host:5432/db",
                "jdbc:postgresql://host:1/db",
                "jdbc:postgresql://host:65535/db",
                "jdbc:postgresql://127.0.0.1:5432/db",
                "jdbc:postgresql://db-1.internal_zone.example/db",
                "jdbc:postgresql://h1,h2:5433,h3/db",
                "jdbc:postgresql://h1:5432,h2:5433/db",
                "jdbc:postgresql://[::1]:5432/db",
                "jdbc:postgresql://[::1]/db",
                "jdbc:postgresql://[2001:db8::1]:5432/db",
                "jdbc:postgresql://[::1]:5432,[::2]:5433,h3/db",
                "jdbc:postgresql://host/my-db",
                "jdbc:postgresql://host/my_db",
                "jdbc:postgresql://host/my.db~1",
                "jdbc:postgresql://host/my%20db",
                "jdbc:postgresql://host/d%C3%A9",
                "jdbc:postgresql://host/d%c3%a9",
                "jdbc:postgresql://host/db?ssl=false&loginTimeout=5",
                "jdbc:postgresql://host/db?ssl=false",
                "jdbc:postgresql://host/db?ApplicationName=identity-1",
                "jdbc:postgresql://host/db?targetServerType=primary&hostRecheckSeconds=10");

        for (String url : urls) {
            assertThat(JdbcUrl.acceptable(url)).as(url).isTrue();
        }
    }

    @Test
    @DisplayName("Refused: an @ anywhere in the authority, in any form the authority can take, and a percent-encoded one")
    void userInfoIsRefused() {
        List<String> urls = List.of(
                "jdbc:postgresql://user@host/db",
                "jdbc:postgresql://user:pw@host/db",
                "jdbc:postgresql://:pw@host/db",
                "jdbc:postgresql://@host/db",
                "jdbc:postgresql://host@/db",
                "jdbc:postgresql://h1,user:pw@h2/db",
                "jdbc:postgresql://user:pw@[::1]:5432/db",
                "jdbc:postgresql://host:5432@host2/db",
                "jdbc:postgresql://host@@host/db",
                "jdbc:postgresql://user%40host/db",
                "jdbc:postgresql://us%3Aer%3Apw%40host/db",
                "jdbc:postgresql://user:pw%40x@host/db",
                "jdbc:postgresql://host%40evil/db",
                "jdbc:postgresql://host:5432%40x/db");

        for (String url : urls) {
            assertThat(JdbcUrl.acceptable(url)).as(url).isFalse();
        }
    }

    @Test
    @DisplayName("Refused: a port outside 1 to 65535, a port that is not a number, an empty host or port, an unclosed bracket")
    void authorityIsRefused() {
        List<String> urls = List.of(
                "jdbc:postgresql://host:0/db",
                "jdbc:postgresql://host:65536/db",
                "jdbc:postgresql://host:99999999/db",
                "jdbc:postgresql://host:100000/db",
                "jdbc:postgresql://host:-1/db",
                "jdbc:postgresql://host:+5/db",
                "jdbc:postgresql://host:port/db",
                "jdbc:postgresql://host:12ab/db",
                "jdbc:postgresql://host:/db",
                "jdbc:postgresql://host:5432:6/db",
                "jdbc:postgresql://:5432/db",
                "jdbc:postgresql:///db",
                "jdbc:postgresql://,host/db",
                "jdbc:postgresql://host,/db",
                "jdbc:postgresql://h1,,h2/db",
                "jdbc:postgresql://[::1/db",
                "jdbc:postgresql://[::1]x/db",
                "jdbc:postgresql://[::1]:/db",
                "jdbc:postgresql://[]/db",
                "jdbc:postgresql://[zz]/db",
                "jdbc:postgresql://::1/db",
                "jdbc:postgresql://ho st/db",
                "jdbc:postgresql://host%2Fx/db",
                "jdbc:postgresql://ho;st/db");

        for (String url : urls) {
            assertThat(JdbcUrl.acceptable(url)).as(url).isFalse();
        }
    }

    @Test
    @DisplayName("Refused: no database, a database with a slash or a character outside the set, a fragment, a malformed escape")
    void databaseIsRefused() {
        List<String> urls = List.of(
                "jdbc:postgresql://host",
                "jdbc:postgresql://host/",
                "jdbc:postgresql://host/?ssl=false",
                "jdbc:postgresql://host:5432",
                "jdbc:postgresql://host?ssl=false",
                "jdbc:postgresql://host/a/b",
                "jdbc:postgresql://host/db/",
                "jdbc:postgresql://host/db;password=x",
                "jdbc:postgresql://host/db;x=1",
                "jdbc:postgresql://host/d b",
                "jdbc:postgresql://host/db%",
                "jdbc:postgresql://host/db%4",
                "jdbc:postgresql://host/db%zz",
                "jdbc:postgresql://host/db%4g",
                "jdbc:postgresql://host/db#fragment",
                "jdbc:postgresql://host/db#",
                "jdbc:postgresql://host/db?ssl=false#fragment",
                "jdbc:postgresql://host#fragment/db",
                "jdbc:postgresql://host/db\n",
                "jdbc:postgresql://host/db ",
                " jdbc:postgresql://host/db");

        for (String url : urls) {
            assertThat(JdbcUrl.acceptable(url)).as(url).isFalse();
        }
    }

    @Test
    @DisplayName("Refused: a parameter that names the user or a password, in any case, in any percent-escaped spelling, with or without a value")
    void credentialParametersAreRefused() {
        List<String> names = List.of(
                "user", "USER", "User", "%75ser", "u%73er", "%55SER",
                "password", "PASSWORD", "Password", "%70assword", "%50assword", "pass%77ord", "p%61ssword", "password%00",
                "sslpassword", "sslPassword", "SSLPASSWORD", "ssl%70assword", "sslpasswordcallback",
                "x_passwd", "passwd", "PASSWD", "my.passwd.here", "pwd", "PWD", "x-pwd", "pwdfile", "%70wd",
                "passphrase", "sslPassphrase", "PASSPHRASE", "my_passphrase_x", "%70assphrase",
                "PGPASSWORD", "db-password", "password-file");
        for (String name : names) {
            for (String query : List.of(name + "=x", name + "=", name, "ssl=false&" + name + "=x",
                    name + "=x&ssl=false", "a=1&" + name + "=x&b=2", name + "=x&" + name + "=y")) {
                String url = BASE + "?" + query;
                assertThat(JdbcUrl.acceptable(url)).as(url).isFalse();
            }
        }
    }

    @Test
    @DisplayName("Refused: an empty query, an empty name, a name outside the plain set, a malformed escape in a name or value, a blank or control character in a value")
    void queryIsRefused() {
        List<String> urls = List.of(
                BASE + "?",
                BASE + "?&",
                BASE + "?ssl=false&",
                BASE + "?&ssl=false",
                BASE + "?=x",
                BASE + "?ssl=false&=x",
                BASE + "?1ssl=false",
                BASE + "?a b=1",
                BASE + "?a;b=1",
                BASE + "?a+b=1",
                BASE + "?a%20b=1",
                BASE + "?a%2Fb=1",
                BASE + "?a%zz=1",
                BASE + "?%zz=1",
                BASE + "?%",
                BASE + "?%4=1",
                BASE + "?a%=1",
                BASE + "?%80=1",
                BASE + "?a=%",
                BASE + "?a=%4",
                BASE + "?a=%zz",
                BASE + "?a=b%4g",
                BASE + "?a=b c",
                BASE + "?a=b\tc",
                BASE + "?a=b\nc",
                BASE + "?a=b\u0000",
                BASE + "?a=b\u007f",
                BASE + "?ssl=false#x");

        for (String url : urls) {
            assertThat(JdbcUrl.acceptable(url)).as(url).isFalse();
        }
    }

    @Test
    @DisplayName("Refused: null, empty, blank, another scheme, and the driver's other spellings of the same URL")
    void shapeIsRefused() {
        assertThat(JdbcUrl.acceptable(null)).isFalse();
        List<String> urls = List.of(
                "",
                " ",
                "\n",
                "jdbc:postgresql:",
                "jdbc:postgresql:db",
                "jdbc:postgresql:///db",
                "jdbc:postgresql:/host/db",
                "jdbc:postgresql:host/db",
                "JDBC:POSTGRESQL://host/db",
                "jdbc:PostgreSQL://host/db",
                "jdbc:postgres://host/db",
                "jdbc:mysql://host/db",
                "jdbc:postgresql+ssl://host/db",
                "postgresql://host/db",
                "postgres://user:pw@host/db",
                "host/db",
                "//host/db",
                "http://host/db",
                "jdbc:postgresql://host/db?ssl=false&amp;password=x",
                "jdbc:postgresql://host/db?ssl=false&amp;ssl=true",
                "jdbc:postgresql://host/db?amp;password=x",
                "jdbc:postgresql://host/db&password=x",
                "jdbc:postgresql://host/db;password=x");

        for (String url : urls) {
            assertThat(JdbcUrl.acceptable(url)).as(url).isFalse();
        }
    }

    @Test
    @DisplayName("Parameters whose name is not a credential are accepted, duplicated ones too, whatever they set: the rule is about credentials in the URL")
    void otherParametersFollowTheRule() {
        List<String> urls = List.of(
                BASE + "?ssl=false&ssl=true",
                BASE + "?options=-c%20statement_timeout%3D5000",
                BASE + "?sslkey=%2Fetc%2Fkey&sslcert=%2Fetc%2Fcert&sslrootcert=%2Fetc%2Froot",
                BASE + "?sslfactoryarg=x&socketFactoryArg=y",
                BASE + "?service=svc&localSocketAddress=127.0.0.1",
                BASE + "?kerberosServerName=postgres&jaasLogin=false",
                BASE + "?loggerLevel=OFF");

        for (String url : urls) {
            assertThat(JdbcUrl.acceptable(url)).as(url).isTrue();
        }
    }

    // --- the property, with a parser of its own -----------------------------------------------------------

    private static final List<String> PASSWORD_WORDS = List.of("password", "passwd", "pwd", "passphrase");

    /** Why the URL is unsafe to hand to the driver, or null; reads the URL without any help from JdbcUrl. */
    static String unsafe(String url) {
        String scheme = "jdbc:postgresql://";
        if (!url.startsWith(scheme)) {
            return "not the jdbc:postgresql:// scheme";
        }
        String rest = url.substring(scheme.length());
        int slash = rest.indexOf('/');
        if (slash < 0) {
            return "no database";
        }
        String authority = rest.substring(0, slash);
        if (authority.indexOf('@') >= 0) {
            return "@ in the authority";
        }
        if (authority.isEmpty()) {
            return "empty authority";
        }
        if (url.indexOf('#') >= 0) {
            return "fragment";
        }
        int question = rest.indexOf('?', slash);
        if (question >= 0) {
            for (String parameter : rest.substring(question + 1).split("&", -1)) {
                int equals = parameter.indexOf('=');
                String name = equals < 0 ? parameter : parameter.substring(0, equals);
                String decoded = lenientDecode(name).toLowerCase(Locale.ROOT);
                if (decoded.equals("user")) {
                    return "parameter user";
                }
                for (String word : PASSWORD_WORDS) {
                    if (decoded.contains(word)) {
                        return "parameter " + decoded;
                    }
                }
            }
        }
        return null;
    }

    /** Percent-decodes what is well formed and leaves the rest as it is. */
    private static String lenientDecode(String name) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c == '%' && i + 2 < name.length() && Character.digit(name.charAt(i + 1), 16) >= 0
                    && Character.digit(name.charAt(i + 2), 16) >= 0) {
                out.append((char) Integer.parseInt(name.substring(i + 1, i + 3), 16));
                i += 2;
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    private static final String[] AUTHORITIES = {"host", "h1,h2", "host:5432", "[::1]:5432", "127.0.0.1", "u@host",
        "u:p@host", "host%40x", "h:0", "h:70000", "host:", "", "[::1", "h1,", "ho st", "a.b-c_d"};
    private static final String[] DATABASES = {"db", "my-db", "d%C3%A9", "a/b", "", "db%", "d%zz", "db;x=1", "db#f",
        "db~1", "d.b"};
    private static final String[] NAME_PARTS = {"user", "User", "pass", "word", "Password", "pwd", "PWD", "passwd",
        "passphrase", "ssl", "x", "_", "-", ".", "%70", "%50", "%75", "%77", "%2F", "%", "a", "amp;", "1", "ord",
        "sslpass", "Ph", "rase", "%00", "%FF"};
    private static final String[] VALUES = {"", "x", "false", "5", "%20", "%", "a b", "%zz", "p@ss", "a=b", "x#y",
        "%41", "?"};

    private static String pick(Random random, String[] from) {
        return from[random.nextInt(from.length)];
    }

    private static String randomName(Random random) {
        StringBuilder name = new StringBuilder();
        int parts = 1 + random.nextInt(4);
        for (int i = 0; i < parts; i++) {
            name.append(pick(random, NAME_PARTS));
        }
        return name.toString();
    }

    static String randomUrl(Random random) {
        StringBuilder url = new StringBuilder(random.nextInt(25) == 0 ? "jdbc:postgresql:" : "jdbc:postgresql://");
        url.append(pick(random, AUTHORITIES)).append(random.nextInt(30) == 0 ? "" : "/").append(pick(random, DATABASES));
        int parameters = random.nextInt(4);
        for (int i = 0; i < parameters; i++) {
            url.append(i == 0 ? '?' : (random.nextInt(12) == 0 ? ';' : '&'));
            url.append(randomName(random));
            if (random.nextInt(8) != 0) {
                url.append('=').append(pick(random, VALUES));
            }
        }
        if (random.nextInt(25) == 0) {
            url.append('#').append(pick(random, VALUES));
        }
        if (random.nextInt(4) == 0 && url.length() > 1) {
            int at = random.nextInt(url.length());
            switch (random.nextInt(3)) {
                case 0 -> url.deleteCharAt(at);
                case 1 -> url.insert(at, "@:/?#%&=[],".charAt(random.nextInt(11)));
                default -> url.setCharAt(at, "@:/?#%&=[],".charAt(random.nextInt(11)));
            }
        }
        return url.toString();
    }

    @Test
    @DisplayName("Property: for every URL the rule accepts, no @ comes before the first / of the authority and no parameter name decodes to a credential word")
    void acceptedUrlsCarryNoCredential() {
        int total = 0;
        int accepted = 0;
        int refusedHostile = 0;
        List<String> unsafeAccepted = new ArrayList<>();
        for (long seed : new long[]{20_260_101L, 20_260_102L, 20_260_103L}) {
            Random random = new Random(seed);
            for (int i = 0; i < 40_000; i++) {
                String url = randomUrl(random);
                total++;
                boolean ok = JdbcUrl.acceptable(url);
                String problem = unsafe(url);
                if (ok) {
                    accepted++;
                    if (problem != null && unsafeAccepted.size() < 10) {
                        unsafeAccepted.add(seed + ": " + url + " -> " + problem);
                    }
                } else if (problem != null) {
                    refusedHostile++;
                }
            }
        }

        assertThat(unsafeAccepted).as("accepted URLs that carry a credential, of %d", total).isEmpty();
        assertThat(total).isGreaterThanOrEqualTo(20_000);
        assertThat(accepted).as("the generator reaches the accepted side").isGreaterThanOrEqualTo(1_000);
        assertThat(refusedHostile).as("the generator reaches the hostile side").isGreaterThanOrEqualTo(10_000);
    }

    @Test
    @DisplayName("The test's own parser flags each hostile shape the table refuses, so the property can fail")
    void independentParserCatches() {
        assertThat(unsafe("jdbc:postgresql://u:p@h/db")).isNotNull();
        assertThat(unsafe("jdbc:postgresql://h/db?%70assword=x")).isNotNull();
        assertThat(unsafe("jdbc:postgresql://h/db?a=1&USER=x")).isNotNull();
        assertThat(unsafe("jdbc:postgresql://h/db?x_PWD=x")).isNotNull();
        assertThat(unsafe("jdbc:postgresql://h/db#f")).isNotNull();
        assertThat(unsafe("jdbc:postgresql://h:5432/db?ssl=false")).isNull();
    }
}
