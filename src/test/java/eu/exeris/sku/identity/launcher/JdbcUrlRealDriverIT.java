package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.LaunchedProcess;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A hostile database URL either stops at the launcher's URL rule, before the PostgreSQL driver is called, or
 * is passed to the driver and nothing of it reaches the output. The driver is the real one, in a JVM of its
 * own whose standard output and standard error are captured; a recording driver registered ahead of it counts
 * the calls. Each URL carries a marker of its own in the position under test.
 */
@DisplayName("A hostile JDBC URL with the real driver: refused before the driver, or absent from the output")
class JdbcUrlRealDriverIT {

    private static final String HOST = "127.0.0.1:1";
    private static final Pattern RESULT = Pattern.compile(
            "RESULT (\\S+) reached=(\\d+) state=(\\S+) class=(\\S+)");

    /** A URL template; {@code {M}} is the marker, {@code {m}} the marker in lower case. */
    private record Case(String id, String template, boolean refusedByTheRule) {
        String url(String marker) {
            return template.replace("{M}", marker).replace("{m}", marker.toLowerCase(java.util.Locale.ROOT));
        }
    }

    private static Case refused(String id, String template) {
        return new Case(id, template, true);
    }

    private static Case passed(String id, String template) {
        return new Case(id, template, false);
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
        // accepted by the rule: the marker sits where the driver reads a host, a database or a value, and the
        // driver gets the URL; it must not write it
        cases.add(passed("host-name", "jdbc:postgresql://{m}.invalid/db?loginTimeout=3&connectTimeout=3"));
        cases.add(passed("database", h + "/{M}"));
        cases.add(passed("parameter-name", h + "/db?{M}=1"));
        for (String name : driverPropertyNames()) {
            String lower = name.toLowerCase(java.util.Locale.ROOT);
            boolean credential = lower.equals("user") || lower.contains("password") || lower.contains("passwd")
                    || lower.contains("pwd") || lower.contains("passphrase");
            cases.add(new Case("property-" + name, h + "/db?" + name + "={M}", credential));
        }
        cases.add(passed("options-encoded", h + "/db?options=-c%20application_name%3D{M}"));
        cases.add(passed("duplicate-value", h + "/db?ssl=false&ssl={M}"));
        return cases;
    }

    /** Every property name the driver reads, so that no parameter is left out for want of a list. */
    private static List<String> driverPropertyNames() {
        try {
            Object[] properties = Class.forName("org.postgresql.PGProperty").getEnumConstants();
            List<String> names = new ArrayList<>();
            for (Object property : properties) {
                names.add((String) property.getClass().getMethod("getName").invoke(property));
            }
            assertThat(names).as("the driver's properties").hasSizeGreaterThan(80).contains("ssl", "options");
            return names;
        } catch (ReflectiveOperationException e) {
            throw new AssertionError("the driver's property list is not readable", e);
        }
    }

    private static String marker() {
        return SecretForms.marker(24);
    }

    private record Outcome(int reached, String state, String type) {
    }

    private record Run(String output, Map<String, Outcome> outcomes) {
    }

    private static Run run(Path dir, Map<String, String> urlsById) throws Exception {
        Path file = dir.resolve("urls.tsv");
        StringBuilder lines = new StringBuilder();
        urlsById.forEach((id, url) -> lines.append(id).append('\t').append(url).append('\n'));
        Files.writeString(file, lines.toString());
        String output;
        try (LaunchedProcess process = LaunchedProcess.startMain(HostileUrlMain.class.getName(), Map.of(),
                List.of(), file.toString())) {
            int status = process.awaitExit(180);
            output = process.output();
            assertThat(status).as(output).isZero();
        }
        Map<String, Outcome> outcomes = new LinkedHashMap<>();
        Matcher m = RESULT.matcher(output);
        while (m.find()) {
            outcomes.put(m.group(1), new Outcome(Integer.parseInt(m.group(2)), m.group(3), m.group(4)));
        }
        assertThat(output).as("the child finished").contains("DONE");
        return new Run(output, outcomes);
    }

    @Test
    @DisplayName("Each hostile URL is refused before the driver or leaves no marker in the output, and the driver never writes an invalid port")
    void corpusAgainstTheRealDriver(@TempDir Path dir) throws Exception {
        List<Case> cases = corpus();
        Map<String, String> markers = new LinkedHashMap<>();
        Map<String, String> urls = new LinkedHashMap<>();
        for (Case c : cases) {
            String marker = marker();
            markers.put(c.id(), marker);
            urls.put(c.id(), c.url(marker));
        }

        Run run = run(dir, urls);

        assertThat(run.outcomes().keySet()).as("every URL was tried").containsExactlyElementsOf(urls.keySet());
        List<String> leaks = new ArrayList<>();
        List<String> reached = new ArrayList<>();
        List<String> wrongState = new ArrayList<>();
        for (Case c : cases) {
            Outcome outcome = run.outcomes().get(c.id());
            if (run.output().contains(markers.get(c.id()))) {
                leaks.add(c.id() + " -> " + urls.get(c.id()).replace(markers.get(c.id()), "<MARKER>"));
            }
            if (c.refusedByTheRule()) {
                if (outcome.reached() != 0) {
                    reached.add(c.id());
                }
                if (!"08001".equals(outcome.state())) {
                    wrongState.add(c.id() + " state=" + outcome.state());
                }
            } else {
                assertThat(outcome.reached()).as(c.id() + " goes to the driver").isEqualTo(1);
            }
        }
        assertThat(reached).as("refused URLs that reached the driver").isEmpty();
        assertThat(wrongState).as("refused URLs that did not end with SQLSTATE 08001").isEmpty();
        org.assertj.core.api.SoftAssertions.assertSoftly(soft -> {
            soft.assertThat(run.output()).as("the driver's invalid-port warning")
                    .doesNotContain("JDBC URL invalid port number");
            soft.assertThat(leaks).as("URLs whose marker reached the output").isEmpty();
        });
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

}
