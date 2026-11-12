package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.LaunchedProcess;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A database URL either stops at the launcher's URL rule, before the PostgreSQL driver is called, or is
 * passed to the driver because every parameter of it is on the allow-list with a value of its grammar. The
 * driver is the real one, in a JVM of its own whose standard output and standard error are captured; a
 * recording driver registered ahead of it counts the calls. Each URL carries a marker of its own in the
 * position under test.
 */
@DisplayName("A hostile JDBC URL with the real driver: refused before the driver, or absent from the output")
class JdbcUrlRealDriverIT {

    private static final String HOST = "127.0.0.1:1";
    private static final Pattern RESULT = Pattern.compile(
            "RESULT (\\S+) reached=(\\d+) state=(\\S+) class=(\\S+)");

    private enum Kind { REFUSED_BEFORE_THE_DRIVER, REACHES_THE_DRIVER }

    /** A URL template; {@code {M}} is the marker, {@code {m}} the marker in lower case. */
    private record Case(String id, String template, Kind kind) {
        String url(String marker) {
            return template.replace("{M}", marker).replace("{m}", marker.toLowerCase(java.util.Locale.ROOT));
        }

        boolean refused() {
            return kind == Kind.REFUSED_BEFORE_THE_DRIVER;
        }
    }

    private static Case refused(String id, String template) {
        return new Case(id, template, Kind.REFUSED_BEFORE_THE_DRIVER);
    }

    private static Case reaches(String id, String template) {
        return new Case(id, template, Kind.REACHES_THE_DRIVER);
    }

    private static List<Case> corpus() {
        String h = "jdbc:postgresql://" + HOST;
        List<Case> cases = new ArrayList<>();
        // user and password in the authority, in every spelling the driver could read as host or port
        cases.add(refused("auth-user-password", "jdbc:postgresql://{M}:{M}@" + HOST + "/db"));
        cases.add(refused("auth-user", "jdbc:postgresql://{M}@" + HOST + "/db"));
        cases.add(refused("auth-empty-user-password", "jdbc:postgresql://:{M}@" + HOST + "/db"));
        cases.add(refused("auth-encoded-at", "jdbc:postgresql://%40{M}/db"));
        cases.add(refused("auth-encoded-user", "jdbc:postgresql://{M}%40" + HOST + "/db"));
        cases.add(refused("auth-ipv6-user", "jdbc:postgresql://{M}:{M}@[::1]:5432/db"));
        cases.add(refused("auth-second-host", "jdbc:postgresql://" + HOST + ",{M}:{M}@h2/db"));
        // the port
        cases.add(refused("port-text", "jdbc:postgresql://127.0.0.1:{M}/db"));
        cases.add(refused("port-text-suffix", "jdbc:postgresql://127.0.0.1:99999999{M}/db"));
        cases.add(refused("port-zero-database", "jdbc:postgresql://127.0.0.1:0/{M}"));
        cases.add(refused("port-too-large-database", "jdbc:postgresql://127.0.0.1:70000/{M}"));
        cases.add(refused("port-empty", "jdbc:postgresql://127.0.0.1:/{M}"));
        cases.add(refused("host-empty", "jdbc:postgresql://:5432/{M}"));
        cases.add(refused("bracket-unclosed", "jdbc:postgresql://[::1/{M}"));
        // the query
        for (String name : List.of("user", "password", "PASSWORD", "%70assword", "sslpassword", "x_passwd", "pwd",
                "passphrase", "sslPassphrase", "PGPASSWORD")) {
            cases.add(refused("query-" + name, h + "/db?" + name + "={M}"));
        }
        cases.add(refused("query-after-harmless", h + "/db?ssl=false&password={M}"));
        cases.add(refused("query-duplicate-user", h + "/db?user=x&user={M}"));
        cases.add(refused("query-in-name", h + "/db?{M}&password={M}"));
        cases.add(refused("query-options-and-password", h + "/db?options=-c%20x%3D{M}&password={M}"));
        cases.add(refused("query-amp", h + "/db?ssl=false&amp;password={M}"));
        cases.add(refused("query-semicolon", h + "/db;password={M}"));
        cases.add(refused("query-malformed-escape", h + "/db?a=%{M}"));
        cases.add(refused("database-malformed-escape", h + "/{M}%"));
        cases.add(refused("fragment", h + "/db#{M}"));
        cases.add(refused("fragment-after-query", h + "/db?ssl=false#{M}"));
        // other spellings of the same URL
        cases.add(refused("no-slashes", "jdbc:postgresql:{M}"));
        cases.add(refused("no-slashes-query", "jdbc:postgresql:db?password={M}"));
        cases.add(refused("three-slashes", "jdbc:postgresql:///{M}"));
        cases.add(refused("three-slashes-query", "jdbc:postgresql:///db?user={M}&password={M}"));
        cases.add(refused("no-database", h + "?password={M}"));
        cases.add(refused("trailing-blank", h + "/db?ssl=false {M}"));
        // outside the allow-list: the marker is a parameter name, a duplicate, a value outside a grammar, or
        // sits in a parameter the table does not list
        cases.add(refused("parameter-name", h + "/db?{M}=1"));
        cases.add(refused("parameter-name-without-value", h + "/db?{M}"));
        cases.add(refused("parameter-name-after-listed", h + "/db?ssl=false&{M}=true"));
        cases.add(refused("options-encoded", h + "/db?options=-c%20application_name%3D{M}"));
        cases.add(refused("options-plain", h + "/db?options={M}"));
        cases.add(refused("duplicate-value", h + "/db?ssl=false&ssl={M}"));
        cases.add(refused("duplicate-equal-value", h + "/db?ssl=false&ssl=false&loginTimeout={M}"));
        cases.add(refused("duplicate-application-name", h + "/db?ApplicationName={M}&ApplicationName={M}"));
        cases.add(refused("duplicate-current-schema", h + "/db?currentSchema={M}&currentSchema={m}"));
        cases.add(refused("name-case-ssl", h + "/db?SSL={M}"));
        cases.add(refused("name-case-application-name", h + "/db?applicationname={M}"));
        cases.add(refused("name-case-current-schema", h + "/db?CurrentSchema={M}"));
        cases.add(refused("name-escaped", h + "/db?ssl%6dode={M}"));
        cases.add(refused("name-with-blank", h + "/db?ApplicationName%20={M}"));
        cases.add(refused("application-name-too-long", h + "/db?ApplicationName={M}{M}{M}"));
        cases.add(refused("application-name-at-sixty-four", h + "/db?ApplicationName={M}{M}" + "a".repeat(16)));
        cases.add(refused("application-name-escape", h + "/db?ApplicationName=%41{M}"));
        cases.add(refused("application-name-blank", h + "/db?ApplicationName={M}%20x"));
        cases.add(refused("application-name-quote", h + "/db?ApplicationName={M}'x"));
        cases.add(refused("application-name-non-ascii", h + "/db?ApplicationName={M}\u00e9"));
        cases.add(refused("application-name-slash", h + "/db?ApplicationName={M}/x"));
        cases.add(refused("current-schema-quoted", h + "/db?currentSchema=\"{M}\""));
        cases.add(refused("current-schema-dollar", h + "/db?currentSchema={M},$user"));
        cases.add(refused("current-schema-empty-identifier", h + "/db?currentSchema={M},,x"));
        cases.add(refused("current-schema-dot", h + "/db?currentSchema={M}.x"));
        cases.add(refused("current-schema-too-long", h + "/db?currentSchema={M}" + "a".repeat(240)));
        cases.add(refused("seconds-text", h + "/db?loginTimeout={M}"));
        cases.add(refused("seconds-above", h + "/db?connectTimeout=86401&socketTimeout={M}"));
        cases.add(refused("boolean-text", h + "/db?tcpKeepAlive={M}"));
        cases.add(refused("sslmode-text", h + "/db?sslmode={M}"));
        cases.add(refused("version-text", h + "/db?assumeMinServerVersion={M}"));
        // every property the driver reads: a marker as the value. A parameter outside the table is refused; a
        // listed one is refused too unless the marker has its grammar, as it has for the two free-form values.
        Set<String> listed = new LinkedHashSet<>(JdbcUrlTable.names());
        Set<String> markerGrammar = Set.of("ApplicationName", "currentSchema");
        for (String name : driverPropertyNames()) {
            String template = h + "/db?" + name + "={M}";
            if (markerGrammar.contains(name)) {
                cases.add(reaches("property-" + name, template));
            } else {
                cases.add(refused((listed.contains(name) ? "listed-outside-grammar-" : "property-") + name, template));
            }
        }
        // the allow-list with values of the grammar: the driver is called and there is no marker to find
        JdbcUrlTable.byName().forEach((name, row) -> {
            cases.add(reaches("listed-first-" + name, h + "/db?" + name + "=" + row.valid().get(0)));
            cases.add(reaches("listed-last-" + name, h + "/db?" + name + "=" + row.valid().get(row.valid().size() - 1)));
        });
        cases.add(reaches("listed-all", h + "/db?" + String.join("&", JdbcUrlTable.byName().entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue().valid().get(0)).toList())));
        // the marker where the grammar lets it stand: a host, a database name, a free-form value
        cases.add(reaches("host-name", "jdbc:postgresql://{m}.invalid/db?loginTimeout=3&connectTimeout=3"));
        cases.add(reaches("host-list", "jdbc:postgresql://" + HOST + ",{m}.invalid:5433/db?loginTimeout=3"));
        cases.add(reaches("database", h + "/{M}"));
        cases.add(reaches("database-escaped", h + "/{M}%20x"));
        cases.add(reaches("application-name", h + "/db?ApplicationName={M}"));
        cases.add(reaches("application-name-with-listed", h + "/db?ssl=false&ApplicationName={M}&loginTimeout=3"));
        cases.add(reaches("application-name-at-sixty-three", h + "/db?ApplicationName={M}{M}" + "a".repeat(15)));
        cases.add(reaches("application-name-punctuation", h + "/db?ApplicationName={M}.-_x"));
        cases.add(reaches("current-schema", h + "/db?currentSchema={M}"));
        cases.add(reaches("current-schema-list", h + "/db?currentSchema={M},{m}_two,Three3"));
        cases.add(reaches("application-name-and-schema-on-an-unresolvable-host",
                "jdbc:postgresql://{m}.invalid/{M}?ApplicationName={M}&currentSchema={M}&connectTimeout=3"));
        return cases;
    }

    /** Every property name the driver reads, so that no parameter is left out for want of a list. */
    private static List<String> driverPropertyNames() {
        List<String> names = JdbcUrlTest.driverPropertyNames();
        assertThat(names).as("the driver's properties").hasSizeGreaterThan(80).contains("ssl", "options");
        return names;
    }

    private static String marker() {
        return SecretForms.marker(24);
    }

    private record Outcome(int reached, String state, String type) {
    }

    private record Run(String output, Map<String, Outcome> outcomes) {
    }

    private static Run run(Path dir, Map<String, String> urlsById) throws Exception {
        return run(dir, urlsById, List.of(), "svc", "pw");
    }

    private static Run run(Path dir, Map<String, String> urlsById, List<String> jvmOptions, String user,
                           String password) throws Exception {
        Path file = dir.resolve("urls.tsv");
        StringBuilder lines = new StringBuilder();
        urlsById.forEach((id, url) -> lines.append(id).append('\t').append(url).append('\n'));
        Files.writeString(file, lines.toString());
        String output;
        try (LaunchedProcess process = LaunchedProcess.startMain(HostileUrlMain.class.getName(), Map.of(),
                jvmOptions, file.toString(), user, password)) {
            int status = process.awaitExit(240);
            output = process.output();
            assertThat(status).as(output.length() > 4_000 ? output.substring(0, 4_000) : output).isZero();
        }
        Map<String, Outcome> outcomes = new LinkedHashMap<>();
        Matcher m = RESULT.matcher(output);
        while (m.find()) {
            outcomes.put(m.group(1), new Outcome(Integer.parseInt(m.group(2)), m.group(3), m.group(4)));
        }
        assertThat(output).as("the child finished").contains("DONE");
        return new Run(output, outcomes);
    }

    /** The marker of each case and its URL, in the order of the corpus. */
    private record Prepared(List<Case> cases, Map<String, String> markers, Map<String, String> urls) {
        static Prepared of(List<Case> cases) {
            Map<String, String> markers = new LinkedHashMap<>();
            Map<String, String> urls = new LinkedHashMap<>();
            for (Case c : cases) {
                String marker = marker();
                markers.put(c.id(), marker);
                urls.put(c.id(), c.url(marker));
            }
            return new Prepared(cases, markers, urls);
        }
    }

    @Test
    @DisplayName("The corpus holds both kinds: URLs refused before the driver, including every driver property outside the table, and URLs of the allow-list that reach it")
    void corpusShape() {
        List<Case> cases = corpus();
        Set<String> ids = new LinkedHashSet<>();
        cases.forEach(c -> assertThat(ids.add(c.id())).as("unique id " + c.id()).isTrue());
        long refused = cases.stream().filter(Case::refused).count();
        long reaches = cases.size() - refused;

        assertThat(refused).isGreaterThan(100);
        assertThat(reaches).isGreaterThan(40);
        for (String name : JdbcUrlTable.names()) {
            assertThat(ids).as("listed parameter " + name).contains("listed-first-" + name, "listed-last-" + name);
        }
        Set<String> listed = new LinkedHashSet<>(JdbcUrlTable.names());
        for (String name : driverPropertyNames()) {
            if (!listed.contains(name)) {
                assertThat(cases.stream().filter(c -> c.id().equals("property-" + name)).findFirst().orElseThrow()
                        .refused()).as("an unlisted property reaches no driver: " + name).isTrue();
            }
        }
    }

    @Test
    @DisplayName("Each URL outside the allow-list is refused before the driver with SQLSTATE 08001, each URL of the allow-list reaches it, and with the driver's default logging nothing of either is written")
    void corpusAgainstTheRealDriver(@TempDir Path dir) throws Exception {
        Prepared corpus = Prepared.of(corpus());

        Run run = run(dir, corpus.urls());

        assertThat(run.outcomes().keySet()).as("every URL was tried").containsExactlyElementsOf(corpus.urls().keySet());
        List<String> leaks = new ArrayList<>();
        List<String> reached = new ArrayList<>();
        List<String> notReached = new ArrayList<>();
        List<String> wrongState = new ArrayList<>();
        for (Case c : corpus.cases()) {
            Outcome outcome = run.outcomes().get(c.id());
            if (run.output().contains(corpus.markers().get(c.id()))) {
                leaks.add(c.id() + " -> " + corpus.urls().get(c.id()).replace(corpus.markers().get(c.id()), "<MARKER>"));
            }
            if (c.refused()) {
                if (outcome.reached() != 0) {
                    reached.add(c.id());
                }
                if (!"08001".equals(outcome.state())) {
                    wrongState.add(c.id() + " state=" + outcome.state());
                }
            } else if (outcome.reached() != 1) {
                notReached.add(c.id() + " reached=" + outcome.reached());
            }
        }
        assertThat(reached).as("refused URLs that reached the driver").isEmpty();
        assertThat(wrongState).as("refused URLs that did not end with SQLSTATE 08001").isEmpty();
        assertThat(notReached).as("URLs of the allow-list that did not reach the driver exactly once").isEmpty();
        org.assertj.core.api.SoftAssertions.assertSoftly(soft -> {
            soft.assertThat(run.output()).as("the driver's invalid-port warning")
                    .doesNotContain("JDBC URL invalid port number");
            soft.assertThat(leaks).as("URLs whose marker reached the output").isEmpty();
        });
    }

    private static final Pattern RECORD_LEVEL = Pattern.compile("^(FINEST|FINER|FINE|CONFIG|INFO|WARNING|SEVERE): ");

    @Test
    @DisplayName("With the driver's logging at ALL: a record quotes only the URL it was given, a host, a port or a database name; a refused URL writes nothing; the role and the password are never written")
    void whatTheDriverWritesAtEveryLevel(@TempDir Path dir) throws Exception {
        Prepared corpus = Prepared.of(corpus());
        Path config = dir.resolve("logging.properties");
        Files.writeString(config, "handlers=java.util.logging.ConsoleHandler\n.level=ALL\n"
                + "java.util.logging.ConsoleHandler.level=ALL\n");
        String user = "role" + marker().toLowerCase(java.util.Locale.ROOT);
        String password = marker();

        Run run = run(dir, corpus.urls(), List.of("-Djava.util.logging.config.file=" + config), user, password);

        List<String> lines = run.output().lines().toList();
        assertThat(lines.stream().filter(l -> RECORD_LEVEL.matcher(l).find()).count())
                .as("the driver writes at FINE when asked to").isGreaterThan(100);
        assertThat(run.output()).as("the role").doesNotContain(user);
        assertThat(run.output()).as("the password").doesNotContain(password);
        assertThat(run.output()).doesNotContain("JDBC URL invalid port number");

        List<String> unexplained = new ArrayList<>();
        Set<String> quotedUrls = new LinkedHashSet<>();
        for (Case c : corpus.cases()) {
            String marker = corpus.markers().get(c.id());
            String url = corpus.urls().get(c.id());
            List<String> carrying = lines.stream().filter(l -> l.contains(marker)).toList();
            if (c.refused()) {
                assertThat(carrying).as("a refused URL writes nothing: " + c.id()).isEmpty();
                continue;
            }
            for (String line : carrying) {
                boolean quotesTheUrl = line.equals("FINE: Connecting with URL: " + url);
                boolean namesTheHost = line.startsWith("FINE: Trying to establish a protocol version 3 connection to ")
                        && line.endsWith(host(url) + ":" + port(url));
                boolean unknownHost = line.endsWith("java.net.UnknownHostException: " + host(url));
                if (quotesTheUrl) {
                    quotedUrls.add(c.id());
                }
                if (!(quotesTheUrl || namesTheHost || unknownHost)) {
                    unexplained.add(c.id() + " -> " + line.replace(marker, "<MARKER>"));
                }
            }
        }
        assertThat(unexplained).as("lines that carry a marker without quoting the URL, its host or its port").isEmpty();
        assertThat(quotedUrls).as("the driver quotes the URL it connects with, so a free-form value of the grammar is in the log")
                .contains("application-name", "current-schema", "database");
        // every URL the driver quotes is one the launcher passed, character for character
        Set<String> passed = new LinkedHashSet<>();
        corpus.cases().stream().filter(c -> !c.refused()).forEach(c -> passed.add(corpus.urls().get(c.id())));
        List<String> quoted = lines.stream().filter(l -> l.startsWith("FINE: Connecting with URL: "))
                .map(l -> l.substring("FINE: Connecting with URL: ".length())).distinct().toList();
        assertThat(passed).containsAll(quoted);
        assertThat(quoted).containsExactlyInAnyOrderElementsOf(passed);
    }

    private static String host(String url) {
        String rest = url.substring("jdbc:postgresql://".length());
        String authority = rest.substring(0, rest.indexOf('/'));
        String first = authority.split(",")[0];
        int colon = first.indexOf(':');
        return colon < 0 ? first : first.substring(0, colon);
    }

    private static String port(String url) {
        String rest = url.substring("jdbc:postgresql://".length());
        String first = rest.substring(0, rest.indexOf('/')).split(",")[0];
        int colon = first.indexOf(':');
        return colon < 0 ? "5432" : first.substring(colon + 1);
    }

    @Test
    @DisplayName("Control: the same child, calling the driver directly with a port that is text, does write the marker, so the capture can see a leak")
    void controlDriverLeaksWhenCalledDirectly(@TempDir Path dir) throws Exception {
        String marker = marker();
        Map<String, String> urls = new LinkedHashMap<>();
        urls.put("DIRECT-port", "jdbc:postgresql://127.0.0.1:" + marker + "/db");
        urls.put("through-launcher", "jdbc:postgresql://127.0.0.1:" + marker + "/db");

        Run run = run(dir, urls);

        assertThat(run.outcomes().get("DIRECT-port").reached()).isEqualTo(1);
        assertThat(run.outcomes().get("through-launcher").reached()).isZero();
        long lines = run.output().lines().filter(l -> l.contains(marker)).count();
        assertThat(lines).as("the driver's own warning holds the marker").isGreaterThanOrEqualTo(1);
        assertThat(run.output()).contains("invalid port number");
    }

    @Test
    @DisplayName("Control: the same child, calling the driver directly with parameters outside the table, does write them, so the refusals are the launcher's")
    void controlDriverAcceptsUnlistedParametersWhenCalledDirectly(@TempDir Path dir) throws Exception {
        String marker = marker();
        Map<String, String> urls = new LinkedHashMap<>();
        urls.put("DIRECT-options", "jdbc:postgresql://127.0.0.1:1/db?options=-c%20x%3D" + marker);
        urls.put("through-launcher", "jdbc:postgresql://127.0.0.1:1/db?options=-c%20x%3D" + marker);

        Run run = run(dir, urls);

        assertThat(run.outcomes().get("DIRECT-options").reached()).isEqualTo(1);
        assertThat(run.outcomes().get("through-launcher").reached()).isZero();
        assertThat(run.outcomes().get("through-launcher").state()).isEqualTo("08001");
    }

}
