package eu.exeris.sku.identity.launcher;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;

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

    // --- the allow-list of query parameters ------------------------------------------------------------

    private static final Path CONFIGURATION = Path.of("docs", "reference", "configuration.md");

    /** A second, valid parameter that is never the one under test. */
    private static String companion(String name) {
        return name.equals("loginTimeout") ? "connectTimeout=1" : "loginTimeout=1";
    }

    /** A third valid parameter, different from the one under test and from its companion. */
    private static String third(String name) {
        return name.equals("stringtype") ? "gssEncMode=prefer" : "stringtype=varchar";
    }

    /** The query in which one parameter under test sits alone, first, last and between two valid ones. */
    private static List<String> positions(String name, String value) {
        String parameter = name + "=" + value;
        String other = companion(name);
        return List.of(parameter, parameter + "&" + other, other + "&" + parameter,
                third(name) + "&" + parameter + "&" + other);
    }

    private static String hex(char c) {
        return "%" + String.format("%02X", (int) c);
    }

    @Test
    @DisplayName("The table in the reference lists exactly the parameters and the bounds the tests below take as the rule")
    void theTableIsTheReferenceTable() throws IOException {
        String text = Files.readString(CONFIGURATION);
        int start = text.indexOf("## The JDBC URL rule");
        int end = text.indexOf("\n## ", start + 10);
        String section = text.substring(start, end);
        Set<String> documented = new LinkedHashSet<>();
        Map<String, String> rows = new LinkedHashMap<>();
        for (String line : section.split("\n")) {
            if (line.startsWith("| `")) {
                String[] cells = line.split("\\|");
                var names = new LinkedHashSet<String>();
                var matcher = java.util.regex.Pattern.compile("`([^`]+)`").matcher(cells[1]);
                while (matcher.find()) {
                    names.add(matcher.group(1));
                }
                documented.addAll(names);
                names.forEach(n -> rows.put(n, cells[2]));
            }
        }

        assertThat(documented).containsExactlyInAnyOrderElementsOf(JdbcUrlTable.names());
        for (String name : List.of("connectTimeout", "socketTimeout", "loginTimeout", "cancelSignalTimeout",
                "hostRecheckSeconds")) {
            assertThat(rows.get(name)).as(name).contains("0 to 86400");
        }
        assertThat(rows.get("prepareThreshold")).contains("0 to 10000");
        assertThat(rows.get("defaultRowFetchSize")).contains("0 to 1000000");
        assertThat(rows.get("ApplicationName")).contains("1 to 63").contains("A-Za-z0-9._-");
        assertThat(rows.get("currentSchema")).contains("A-Za-z0-9_").contains("255");
        assertThat(rows.get("assumeMinServerVersion")).contains("up to six digits");
        assertThat(rows.get("ssl")).contains("`true` or `false`");
        assertThat(rows.get("sslmode")).contains("`verify-ca`", "`verify-full`");
        assertThat(rows.get("gssEncMode")).doesNotContain("verify");
        assertThat(rows.get("channelBinding")).doesNotContain("allow");
        assertThat(section.replaceAll("\\s+", " ")).contains("Names are matched exactly, in the case above, "
                + "without percent-escapes; a value holds no percent-escape, blank or control character.");
    }

    @Test
    @DisplayName("The test's own grammar agrees with the values it lists as inside and outside each row")
    void theRowsAreConsistent() {
        for (JdbcUrlTable.Row row : JdbcUrlTable.ROWS) {
            assertThat(row.valid()).as(row.names().toString()).allSatisfy(v -> assertThat(row.grammar().test(v))
                    .as("valid " + v).isTrue());
            assertThat(row.invalid()).as(row.names().toString()).isNotEmpty().allSatisfy(v ->
                    assertThat(row.grammar().test(v)).as("invalid " + v).isFalse());
        }
    }

    @Test
    @DisplayName("Every row of the table: a value of its grammar is accepted, alone, first, last and between others")
    void everyRowAcceptsItsGrammar() {
        for (JdbcUrlTable.Row row : JdbcUrlTable.ROWS) {
            for (String name : row.names()) {
                for (String value : row.valid()) {
                    for (String query : positions(name, value)) {
                        String url = BASE + "?" + query;
                        assertThat(JdbcUrl.acceptable(url)).as(abbreviated(url)).isTrue();
                    }
                }
            }
        }
    }

    @Test
    @DisplayName("Every row of the table: a value just outside its grammar is refused wherever the parameter sits")
    void everyRowRefusesOutsideItsGrammar() {
        for (JdbcUrlTable.Row row : JdbcUrlTable.ROWS) {
            for (String name : row.names()) {
                for (String value : row.invalid()) {
                    for (String query : positions(name, value)) {
                        String url = BASE + "?" + query;
                        assertThat(JdbcUrl.acceptable(url)).as(abbreviated(url)).isFalse();
                    }
                }
            }
        }
    }

    private static String abbreviated(String url) {
        String shown = url.length() > 160 ? url.substring(0, 160) + "..." : url;
        return shown.replace("\u0000", "\\0").replace("\n", "\\n").replace("\t", "\\t");
    }

    @Test
    @DisplayName("The bounds are exactly the documented ones: seconds 0 to 86400, threshold 0 to 10000, fetch size 0 to 1000000, 63 and 255 characters, groups of six digits")
    void theBoundsAreTheDocumentedOnes() {
        Map<String, long[]> numbers = new LinkedHashMap<>();
        for (String name : List.of("connectTimeout", "socketTimeout", "loginTimeout", "cancelSignalTimeout",
                "hostRecheckSeconds")) {
            numbers.put(name, new long[]{86_400});
        }
        numbers.put("prepareThreshold", new long[]{10_000});
        numbers.put("defaultRowFetchSize", new long[]{1_000_000});
        numbers.forEach((name, maximum) -> {
            long max = maximum[0];
            assertThat(JdbcUrl.acceptable(BASE + "?" + name + "=0")).as(name + "=0").isTrue();
            assertThat(JdbcUrl.acceptable(BASE + "?" + name + "=" + max)).as(name + " at the maximum").isTrue();
            assertThat(JdbcUrl.acceptable(BASE + "?" + name + "=" + (max - 1))).isTrue();
            assertThat(JdbcUrl.acceptable(BASE + "?" + name + "=" + (max + 1))).as(name + " above").isFalse();
            assertThat(JdbcUrl.acceptable(BASE + "?" + name + "=-1")).as(name + " negative").isFalse();
            assertThat(JdbcUrl.acceptable(BASE + "?" + name + "=-0")).isFalse();
            assertThat(JdbcUrl.acceptable(BASE + "?" + name + "=%2B1")).as("escaped plus").isFalse();
            assertThat(JdbcUrl.acceptable(BASE + "?" + name + "=+1")).as("leading plus").isFalse();
            assertThat(JdbcUrl.acceptable(BASE + "?" + name + "=007")).as("leading zeros").isTrue();
            assertThat(JdbcUrl.acceptable(BASE + "?" + name + "=")).as("empty").isFalse();
            assertThat(JdbcUrl.acceptable(BASE + "?" + name + "=\u0661\u0662")).as("Arabic-Indic digits").isFalse();
            assertThat(JdbcUrl.acceptable(BASE + "?" + name + "=\uFF11")).as("full-width digit").isFalse();
            assertThat(JdbcUrl.acceptable(BASE + "?" + name + "=0x1F")).as("hexadecimal").isFalse();
            assertThat(JdbcUrl.acceptable(BASE + "?" + name + "=123456789012345678901234567890"))
                    .as("30 digits").isFalse();
        });
        assertThat(JdbcUrl.acceptable(BASE + "?ApplicationName=" + "a".repeat(63))).isTrue();
        assertThat(JdbcUrl.acceptable(BASE + "?ApplicationName=" + "a".repeat(64))).isFalse();
        assertThat(JdbcUrl.acceptable(BASE + "?ApplicationName=a")).isTrue();
        assertThat(JdbcUrl.acceptable(BASE + "?ApplicationName=")).isFalse();
        assertThat(JdbcUrl.acceptable(BASE + "?currentSchema=" + "a".repeat(255))).isTrue();
        assertThat(JdbcUrl.acceptable(BASE + "?currentSchema=" + "a".repeat(256))).isFalse();
        assertThat(JdbcUrl.acceptable(BASE + "?currentSchema=" + "a,".repeat(127) + "a")).as("255 with commas").isTrue();
        assertThat(JdbcUrl.acceptable(BASE + "?currentSchema=" + "a,".repeat(128) + "a")).as("257 with commas").isFalse();
        assertThat(JdbcUrl.acceptable(BASE + "?assumeMinServerVersion=999999.999999.999999")).isTrue();
        assertThat(JdbcUrl.acceptable(BASE + "?assumeMinServerVersion=1000000")).isFalse();
        assertThat(JdbcUrl.acceptable(BASE + "?assumeMinServerVersion=1.2.3.4")).isFalse();
    }

    @Test
    @DisplayName("A value that holds a percent-escape, a blank or a control character is refused for every row, whatever the value would otherwise be")
    void escapesBlanksAndControlsInValues() {
        for (JdbcUrlTable.Row row : JdbcUrlTable.ROWS) {
            for (String name : row.names()) {
                for (String value : row.valid()) {
                    List<String> spoiled = new ArrayList<>(List.of(value + "%41", value + "%", "%" + value,
                            value + " ", " " + value, value + "\t", value + "\n", value + "\r", value + "\u0000",
                            value + "\u007f", value + "\u0085", value + "\u00a0", value + "=", value + "=x",
                            value + "%20", value + "%0A", value + "%00"));
                    spoiled.add(hex(value.charAt(0)) + value.substring(1));
                    spoiled.add(value.substring(0, value.length() - 1) + hex(value.charAt(value.length() - 1)));
                    for (String bad : spoiled) {
                        String url = BASE + "?" + name + "=" + bad;
                        assertThat(JdbcUrl.acceptable(url)).as(abbreviated(url)).isFalse();
                    }
                }
            }
        }
    }

    @Test
    @DisplayName("Names are exact: another case, a percent-escaped letter, a blank, a dot or any other addition makes a parameter another one, which is not listed")
    void nameSpellings() {
        for (String name : JdbcUrlTable.names()) {
            JdbcUrlTable.Row row = JdbcUrlTable.byName().get(name);
            String value = row.valid().get(0);
            List<String> spellings = new ArrayList<>(List.of(name.toUpperCase(java.util.Locale.ROOT),
                    name.toLowerCase(java.util.Locale.ROOT),
                    Character.toUpperCase(name.charAt(0)) + name.substring(1),
                    Character.toLowerCase(name.charAt(0)) + name.substring(1),
                    name + " ", " " + name, name + "\t", name + ".", "." + name, name + "%", name + "%20",
                    name + "x", "x" + name, name + name, name + "_", name + "-", name + "\u0000",
                    name + "\u00a0", name.substring(0, 1) + "." + name.substring(1), name + ".x", name + "[]",
                    hex(name.charAt(0)) + name.substring(1),
                    name.substring(0, name.length() - 1) + hex(name.charAt(name.length() - 1)),
                    name.substring(0, 1) + "%" + name.substring(1)));
            for (String spelling : spellings) {
                if (spelling.equals(name)) {
                    continue;
                }
                String url = BASE + "?" + spelling + "=" + value;
                assertThat(JdbcUrl.acceptable(url)).as(abbreviated(url)).isFalse();
            }
            assertThat(JdbcUrl.acceptable(BASE + "?" + name + "=" + value)).as("the exact spelling").isTrue();
        }
        for (String url : List.of(BASE + "?SSL=true", BASE + "?Ssl=true", BASE + "?sSL=true", BASE + "?ssl%6dode=require",
                BASE + "?ssl%6Dode=require", BASE + "?%73slmode=require", BASE + "?sslmode =require",
                BASE + "?sslmode=require&sslmode =require", BASE + "?ssl.mode=require", BASE + "?ssl.=true",
                BASE + "?applicationname=x", BASE + "?applicationName=x", BASE + "?APPLICATIONNAME=x",
                BASE + "?Applicationname=x", BASE + "?CurrentSchema=public", BASE + "?currentschema=public",
                BASE + "?connecttimeout=1", BASE + "?ConnectTimeout=1", BASE + "?connectTimeOut=1",
                BASE + "?preparethreshold=1", BASE + "?stringType=varchar", BASE + "?StringType=varchar",
                BASE + "?assumeMinServerVersion%20=12", BASE + "?targetservertype=any",
                BASE + "?GSSEncMode=require", BASE + "?gssencmode=require", BASE + "?channelbinding=require")) {
            assertThat(JdbcUrl.acceptable(url)).as(url).isFalse();
        }
    }

    @Test
    @DisplayName("A parameter without a value, with an empty value or with a second = is refused, alone or among valid ones")
    void parametersWithoutAValue() {
        for (String name : JdbcUrlTable.names()) {
            for (String query : List.of(name, name + "=", name + "&" + companion(name), companion(name) + "&" + name,
                    name + "=&" + companion(name), companion(name) + "&" + name + "=",
                    name + "==", "=" + name)) {
                String url = BASE + "?" + query;
                assertThat(JdbcUrl.acceptable(url)).as(abbreviated(url)).isFalse();
            }
        }
    }

    @Test
    @DisplayName("A parameter that appears twice is refused, with an equal value and with a different one, next to each other or apart")
    void duplicates() {
        for (JdbcUrlTable.Row row : JdbcUrlTable.ROWS) {
            for (String name : row.names()) {
                String first = row.valid().get(0);
                String second = row.valid().get(row.valid().size() - 1);
                List<String> queries = new ArrayList<>(List.of(
                        name + "=" + first + "&" + name + "=" + first,
                        name + "=" + first + "&" + companion(name) + "&" + name + "=" + first,
                        name + "=" + second + "&" + name + "=" + second + "&" + name + "=" + second));
                if (!first.equals(second)) {
                    queries.add(name + "=" + first + "&" + name + "=" + second);
                    queries.add(name + "=" + second + "&" + companion(name) + "&" + name + "=" + first);
                }
                for (String query : queries) {
                    String url = BASE + "?" + query;
                    assertThat(JdbcUrl.acceptable(url)).as(abbreviated(url)).isFalse();
                }
            }
        }
        assertThat(JdbcUrl.acceptable(BASE + "?ssl=true&ssl=true")).isFalse();
        assertThat(JdbcUrl.acceptable(BASE + "?ssl=false&ssl=true")).isFalse();
        assertThat(JdbcUrl.acceptable(BASE + "?ssl=false&sslmode=require&ssl=false")).isFalse();
    }

    /** The names of the driver's own properties, read from its enum so that none is left out for want of a list. */
    static List<String> driverPropertyNames() {
        try {
            Object[] properties = Class.forName("org.postgresql.PGProperty").getEnumConstants();
            List<String> names = new ArrayList<>();
            for (Object property : properties) {
                names.add((String) property.getClass().getMethod("getName").invoke(property));
            }
            return names;
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("the driver's property list is not readable", e);
        }
    }

    @Test
    @DisplayName("Every property of the driver that is not in the table is refused, with any value; a property the driver gains later is refused too")
    void unlistedDriverPropertiesAreRefused() {
        List<String> driver = driverPropertyNames();
        Set<String> listed = new LinkedHashSet<>(JdbcUrlTable.names());
        assertThat(driver).as("the driver's properties").hasSizeGreaterThan(80).contains("ssl", "options", "user",
                "password");
        assertThat(driver).as("every listed parameter is a property of the driver").containsAll(listed);

        List<String> values = List.of("x", "true", "false", "1", "0", "5", "require", "disable", "public", "12",
                "14.2", "any", "varchar", "unspecified", "prefer", "a,b", "off", "10", "");
        int refusedNames = 0;
        for (String name : driver) {
            if (listed.contains(name)) {
                continue;
            }
            refusedNames++;
            for (String value : values) {
                assertThat(JdbcUrl.acceptable(BASE + "?" + name + "=" + value)).as(name + "=" + value).isFalse();
                assertThat(JdbcUrl.acceptable(BASE + "?ssl=false&" + name + "=" + value)).as(name + "=" + value).isFalse();
            }
            assertThat(JdbcUrl.acceptable(BASE + "?" + name)).as(name).isFalse();
        }
        assertThat(refusedNames).isEqualTo(driver.size() - listed.size()).isGreaterThan(60);

        // the set of property names the rule accepts is the table and nothing the driver defines besides
        List<String> acceptedByTheRule = new ArrayList<>();
        for (String name : driver) {
            for (String value : values) {
                if (JdbcUrl.acceptable(BASE + "?" + name + "=" + value)) {
                    acceptedByTheRule.add(name);
                    break;
                }
            }
        }
        assertThat(acceptedByTheRule).containsExactlyInAnyOrderElementsOf(listed);

        for (String added : List.of("someFuturePropertyOfTheDriver", "futureSslOption", "futureNegotiation",
                "future_negotiation", "targetServerTypeX", "ReadOnlyMode2", "requireAuth2", "maxResultBuffer2")) {
            assertThat(driver).as("not a property of this driver version").doesNotContain(added);
            assertThat(JdbcUrl.acceptable(BASE + "?" + added + "=true")).as(added).isFalse();
        }
    }

    @Test
    @DisplayName("Every parameter of the table together is accepted, in either order; one parameter outside the table among them refuses the URL")
    void everyParameterTogether() {
        List<String> parameters = new ArrayList<>();
        JdbcUrlTable.byName().forEach((name, row) -> parameters.add(name + "=" + row.valid().get(0)));
        String forward = String.join("&", parameters);
        List<String> reversed = new ArrayList<>(parameters);
        java.util.Collections.reverse(reversed);

        assertThat(JdbcUrl.acceptable(BASE + "?" + forward)).isTrue();
        assertThat(JdbcUrl.acceptable(BASE + "?" + String.join("&", reversed))).isTrue();
        for (String extra : List.of("options=x", "user=x", "loggerLevel=OFF", "socketFactory=x", "x=1",
                "ssl=true", "sslmode=require")) {
            assertThat(JdbcUrl.acceptable(BASE + "?" + forward + "&" + extra)).as(extra).isFalse();
            assertThat(JdbcUrl.acceptable(BASE + "?" + extra + "&" + forward)).as(extra).isFalse();
        }
    }

    @Test
    @DisplayName("Parameters of the earlier, wider rule are refused: free text, files, sockets, classes, logging, duplicates and every alias of a credential")
    void parametersOutsideTheListAreRefused() {
        List<String> urls = List.of(
                BASE + "?ssl=false&ssl=true",
                BASE + "?options=-c%20statement_timeout%3D5000",
                BASE + "?options=-c%20statement_timeout=5000",
                BASE + "?sslkey=%2Fetc%2Fkey&sslcert=%2Fetc%2Fcert&sslrootcert=%2Fetc%2Froot",
                BASE + "?sslkey=x", BASE + "?sslcert=x", BASE + "?sslrootcert=x",
                BASE + "?sslfactoryarg=x&socketFactoryArg=y",
                BASE + "?sslfactoryarg=x", BASE + "?socketFactoryArg=y",
                BASE + "?service=svc&localSocketAddress=127.0.0.1",
                BASE + "?service=svc", BASE + "?localSocketAddress=127.0.0.1",
                BASE + "?kerberosServerName=postgres&jaasLogin=false",
                BASE + "?kerberosServerName=postgres", BASE + "?jaasLogin=false",
                BASE + "?loggerLevel=OFF", BASE + "?loggerLevel=DEBUG", BASE + "?loggerFile=x",
                BASE + "?socketFactory=x", BASE + "?sslfactory=x", BASE + "?authenticationPluginClassName=x",
                BASE + "?sslhostnameverifier=x", BASE + "?sslpasswordcallback=x", BASE + "?xmlFactoryFactory=x",
                BASE + "?passfile=x", BASE + "?PGPORT=5432", BASE + "?PGHOST=h", BASE + "?PGDBNAME=db");

        for (String url : urls) {
            assertThat(JdbcUrl.acceptable(url)).as(url).isFalse();
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
            Set<String> seen = new LinkedHashSet<>();
            Map<String, JdbcUrlTable.Row> allowed = JdbcUrlTable.byName();
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
                if (!allowed.containsKey(name)) {
                    return "parameter not in the table: " + name;
                }
                if (equals < 0) {
                    return "parameter without a value: " + name;
                }
                if (!seen.add(name)) {
                    return "parameter twice: " + name;
                }
                if (!allowed.get(name).grammar().test(parameter.substring(equals + 1))) {
                    return "value outside the grammar of " + name;
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

    private static final List<String> TABLE_NAMES = JdbcUrlTable.names();

    private static String listedName(Random random) {
        String name = TABLE_NAMES.get(random.nextInt(TABLE_NAMES.size()));
        return switch (random.nextInt(12)) {
            case 0 -> name.toUpperCase(Locale.ROOT);
            case 1 -> name + " ";
            case 2 -> Character.toLowerCase(name.charAt(0)) + name.substring(1).toUpperCase(Locale.ROOT);
            case 3 -> "%" + String.format("%02x", (int) name.charAt(0)) + name.substring(1);
            default -> name;
        };
    }

    private static String listedValue(Random random, String name) {
        JdbcUrlTable.Row row = JdbcUrlTable.byName().get(name);
        if (row == null) {
            return pick(random, VALUES);
        }
        return switch (random.nextInt(8)) {
            case 0 -> pick(random, VALUES);
            case 1, 2, 3 -> row.invalid().get(random.nextInt(row.invalid().size()));
            default -> row.valid().get(random.nextInt(row.valid().size()));
        };
    }

    /** A URL with a valid authority and database, and a query that mostly draws on the table. */
    static String randomListedUrl(Random random) {
        StringBuilder url = new StringBuilder(BASE);
        int parameters = 1 + random.nextInt(4);
        List<String> names = new ArrayList<>();
        for (int i = 0; i < parameters; i++) {
            String name = !names.isEmpty() && random.nextInt(10) == 0 ? names.get(random.nextInt(names.size()))
                    : listedName(random);
            names.add(name);
            url.append(i == 0 ? '?' : '&').append(name);
            if (random.nextInt(25) != 0) {
                url.append('=').append(listedValue(random, name));
            }
        }
        return url.toString();
    }

    @Test
    @DisplayName("Property: on URLs drawn from the table, with values at and outside each grammar, the rule accepts exactly what the independent parser of the table accepts")
    void listedParametersAgreeWithTheTable() {
        int total = 0;
        int accepted = 0;
        List<String> disagreements = new ArrayList<>();
        for (long seed : new long[]{20_260_201L, 20_260_202L, 20_260_203L}) {
            Random random = new Random(seed);
            for (int i = 0; i < 30_000; i++) {
                String url = randomListedUrl(random);
                total++;
                boolean ok = JdbcUrl.acceptable(url);
                boolean expected = unsafe(url) == null;
                accepted += ok ? 1 : 0;
                if (ok != expected && disagreements.size() < 10) {
                    disagreements.add(seed + ": " + abbreviated(url) + " -> rule " + ok + ", table " + expected);
                }
            }
        }

        assertThat(disagreements).as("URLs on which the rule and the table differ, of %d", total).isEmpty();
        assertThat(accepted).as("the generator reaches the accepted side").isGreaterThanOrEqualTo(5_000);
        assertThat(total - accepted).as("and the refused side").isGreaterThanOrEqualTo(30_000);
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
        assertThat(unsafe("jdbc:postgresql://h/db?options=x")).isNotNull();
        assertThat(unsafe("jdbc:postgresql://h/db?ssl=false&ssl=false")).isNotNull();
        assertThat(unsafe("jdbc:postgresql://h/db?ssl")).isNotNull();
        assertThat(unsafe("jdbc:postgresql://h/db?SSL=true")).isNotNull();
        assertThat(unsafe("jdbc:postgresql://h/db?connectTimeout=86401")).isNotNull();
        assertThat(unsafe("jdbc:postgresql://h/db?connectTimeout=86400&ApplicationName=a.b-c_1")).isNull();
    }
}
