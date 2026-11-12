package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.LaunchedProcess;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assumptions.assumeThat;

/**
 * The JDBC URL rule of the configuration reference and the "covered / not covered" sentences of the launcher
 * reference's secrets section, each exercised. A sentence is looked up in the document first, so that a
 * change to the document without a change here fails.
 */
@DisplayName("The references on the database URL and on the secrets in the output are what the launcher does")
class DatabaseUrlDocumentationTest {

    private static final Path CONFIGURATION = Path.of("docs", "reference", "configuration.md");
    private static final Path LAUNCHER = Path.of("docs", "reference", "launcher.md");

    private JulState state;
    private PrintStream standardError;

    @BeforeEach
    void save() {
        state = new JulState();
        standardError = System.err;
    }

    @AfterEach
    void restore() {
        System.setErr(standardError);
        state.close();
    }

    private static String section(Path file, String heading) throws IOException {
        String text = Files.readString(file);
        int start = text.indexOf(heading);
        assertThat(start).as(heading).isGreaterThanOrEqualTo(0);
        int end = text.indexOf("\n## ", start + heading.length());
        return text.substring(start, end < 0 ? text.length() : end);
    }

    private static void sentence(String document, String text) {
        assertThat(document.replaceAll("\\s+", " ")).as("the document says: " + text).contains(text);
    }

    // --- the JDBC URL rule -----------------------------------------------------------------------------

    @Test
    @DisplayName("Each bullet of 'The JDBC URL rule' holds: scheme, hosts and ports, user-info, database, fragment, query")
    void jdbcUrlRule() throws IOException {
        String rule = section(CONFIGURATION, "## The JDBC URL rule");
        sentence(rule, "The scheme is `jdbc:postgresql://`.");
        sentence(rule, "separated by commas");
        sentence(rule, "an IPv6 address in brackets, with an optional port from 1 to 65535");
        sentence(rule, "an `@` anywhere in the authority is a refusal");
        sentence(rule, "letters, digits and `. _ ~ -`, with well-formed percent-escapes");
        sentence(rule, "A URL without one is refused, and so is a fragment (`#`).");
        sentence(rule, "A parameter named `user`, `password` or `sslpassword`, or any name that contains `password`, "
                + "`passwd`, `pwd` or `passphrase` in any case or percent-escaped spelling, is refused");

        assertThat(JdbcUrl.acceptable("jdbc:postgresql://h1,h2:5433,[::1]:5432/my-db_1.x~y%20z")).isTrue();
        assertThat(JdbcUrl.acceptable("jdbc:postgresql://host:1/db")).isTrue();
        assertThat(JdbcUrl.acceptable("jdbc:postgresql://host:65535/db")).isTrue();
        assertThat(JdbcUrl.acceptable("jdbc:postgresql://host:0/db")).isFalse();
        assertThat(JdbcUrl.acceptable("jdbc:postgresql://host:65536/db")).isFalse();
        assertThat(JdbcUrl.acceptable("jdbc:postgresql://u:p@host/db")).isFalse();
        assertThat(JdbcUrl.acceptable("jdbc:postgresql://host/db")).isTrue();
        assertThat(JdbcUrl.acceptable("jdbc:postgresql://host")).isFalse();
        assertThat(JdbcUrl.acceptable("jdbc:postgresql://host/db#f")).isFalse();
        for (String name : List.of("user", "password", "sslpassword", "Xpasswd", "PWD", "PassPhrase", "%70assword")) {
            assertThat(JdbcUrl.acceptable("jdbc:postgresql://host/db?" + name + "=x")).as(name).isFalse();
        }
    }

    @Test
    @DisplayName("A URL that does not start with jdbc:postgresql: is a configuration problem; one that starts with it and has another form is refused on open with SQLSTATE 08001 and a message that names no part of it")
    void whereTheUrlIsRefused() throws IOException {
        String rule = section(CONFIGURATION, "## The JDBC URL rule");
        sentence(rule, "A URL that does not start with `jdbc:postgresql:` is a configuration problem (status 78) found "
                + "while the settings are read.");
        sentence(rule, "refused when the connection is opened: `serve` and `bootstrap-owner` end with status 69, "
                + "`migrate` with status 1, all with SQLSTATE 08001 and a message that names no part of the URL.");
        String marker = SecretForms.marker();
        LauncherEnvironment in = new LauncherEnvironment(Map.of("EXERIS_DATABASE_URL", "postgresql://u:" + marker + "@h/d",
                "EXERIS_DATABASE_USER", "u", "EXERIS_DATABASE_PASSWORD", "p"));

        assertThat(DatabaseSettings.read(in, "EXERIS_DATABASE")).isNull();
        assertThat(String.join("\n", in.problems())).doesNotContain(marker);

        String host = "h" + SecretForms.lowerCaseMarker();
        for (String url : List.of("jdbc:postgresql://u:" + marker + "@" + host + "/db", "jdbc:postgresql:" + marker,
                "jdbc:postgresql://" + host + ":" + marker + "/db",
                "jdbc:postgresql://" + host + "/db?password=" + marker)) {
            LauncherEnvironment ok = new LauncherEnvironment(Map.of("EXERIS_DATABASE_URL", url,
                    "EXERIS_DATABASE_USER", "u", "EXERIS_DATABASE_PASSWORD", "p"));
            DatabaseSettings settings = DatabaseSettings.read(ok, "EXERIS_DATABASE");
            assertThat(settings).as(url).isNotNull();
            assertThatThrownBy(settings::open).isInstanceOfSatisfying(SQLException.class, e -> {
                assertThat(e.getSQLState()).isEqualTo("08001");
                assertThat(e.getMessage()).doesNotContain(marker).doesNotContain(host);
            });
            assertThat(settings.toString()).contains("password=<withheld>");
        }
    }

    @Test
    @DisplayName("migrate with a refused URL ends with status 1 and SQLSTATE 08001, and prints nothing of the URL")
    void migrateRefusesTheUrl() throws Exception {
        String marker = SecretForms.marker();
        Map<String, String> env = Map.of(
                "EXERIS_MIGRATE_DATABASE_URL", "jdbc:postgresql://svc:" + marker + "@127.0.0.1:1/identity",
                "EXERIS_MIGRATE_DATABASE_USER", "svc",
                "EXERIS_MIGRATE_DATABASE_PASSWORD", SecretForms.marker());

        try (LaunchedProcess process = LaunchedProcess.start(env, "migrate")) {
            int status = process.awaitExit(60);

            assertThat(status).as(process.output()).isEqualTo(1);
            assertThat(process.output()).contains("SQLSTATE 08001").doesNotContain(marker)
                    .doesNotContain("invalid port").doesNotContain("127.0.0.1");
        }
    }

    // --- the secrets in the output ---------------------------------------------------------------------

    @Test
    @DisplayName("Not covered, as documented: text a library writes to the standard error itself is not redacted")
    void standardStreamsAreNotCovered() throws IOException {
        sentence(Files.readString(LAUNCHER), "Not covered: anything a library writes directly to the standard output or "
                + "the standard error");
        String secret = SecretForms.marker();
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
        ForeignLogs.begin(secret);

        System.err.println("written directly " + secret);

        assertThat(captured.toString(StandardCharsets.UTF_8)).contains(secret);
    }

    @Test
    @DisplayName("Not covered, as documented: a logging configuration reloaded after the command started writes unredacted")
    void reloadedConfigurationIsNotCovered() throws Exception {
        sentence(Files.readString(LAUNCHER), "a logging configuration that is reset or reloaded afterwards");
        String secret = SecretForms.marker();
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        System.setErr(new PrintStream(captured, true, StandardCharsets.UTF_8));
        ForeignLogs.begin(secret);

        LogManager.getLogManager().readConfiguration();
        Logger root = Logger.getLogger("");
        assumeThat(root.getHandlers()).as("the default configuration installs a console handler").isNotEmpty();
        Logger logger = Logger.getLogger("third.party.reloaded." + SecretForms.lowerCaseMarker());
        logger.log(Level.SEVERE, "after the reload " + secret);
        for (java.util.logging.Handler handler : root.getHandlers()) {
            handler.flush();
        }

        assertThat(captured.toString(StandardCharsets.UTF_8)).contains(secret);
        ForeignLogs.begin(secret);
        captured.reset();
        logger.log(Level.SEVERE, "after the next begin " + secret);
        for (java.util.logging.Handler handler : root.getHandlers()) {
            handler.flush();
        }
        assertThat(captured.toString(StandardCharsets.UTF_8)).doesNotContain(secret);
    }

    @Test
    @DisplayName("The Hikari pool logs through SLF4J, and this class path has no SLF4J binding, so that logging is discarded")
    void slf4jIsDiscarded() throws Exception {
        sentence(Files.readString(LAUNCHER), "with no SLF4J binding on the class path (this distribution has none) that "
                + "logging is discarded");
        Class<?> loggerFactory = Class.forName("org.slf4j.LoggerFactory");
        Object factory = loggerFactory.getMethod("getILoggerFactory").invoke(null);
        Class<?> provider = Class.forName("org.slf4j.spi.SLF4JServiceProvider");

        assertThat(factory.getClass().getSimpleName()).isEqualTo("NOPLoggerFactory");
        assertThat(java.util.ServiceLoader.load(provider).findFirst()).isEmpty();
    }

    @Test
    @DisplayName("Covered, as documented: the wrapper is in the root logger and in every logger that exists, and the record that cannot be rewritten is (log record withheld)")
    void coveredSentences() throws IOException {
        String launcher = Files.readString(LAUNCHER);
        sentence(launcher, "The wrapper is installed in the JVM's root logger and in every logger that exists when the "
                + "command starts");
        sentence(launcher, "A record that cannot be rewritten is written as `(log record withheld)`.");
        sentence(launcher, "A secret that becomes known later (the content of the owner password file) is added to the "
                + "secrets as soon as it has been read.");
        sentence(launcher, "its exception is replaced by the class names of the exception and of its causes");
        ForeignLogsTest.Capture capture = new ForeignLogsTest.Capture();
        state.replaceRootHandlers(capture);
        Logger existing = Logger.getLogger("third.party.exists." + SecretForms.lowerCaseMarker());
        existing.setUseParentHandlers(false);
        ForeignLogsTest.Capture own = new ForeignLogsTest.Capture();
        existing.addHandler(own);
        String secret = SecretForms.marker();

        ForeignLogs.begin(secret);
        Logger.getLogger("").log(Level.SEVERE, "root " + secret);
        existing.log(Level.SEVERE, "existing " + secret);

        assertThat(capture.only()).doesNotContain(secret);
        assertThat(own.only()).doesNotContain(secret);
    }
}
