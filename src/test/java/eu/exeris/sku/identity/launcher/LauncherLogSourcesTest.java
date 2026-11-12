package eu.exeris.sku.identity.launcher;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The launcher writes no text that did not originate in its own constants except through
 * {@link LauncherLog}, which redacts it.
 *
 * <p>Reach: every source under {@code src/main/java}. The launcher package builds {@code IdentityComposition},
 * which wires the {@code http}, {@code auth}, {@code wiring}, {@code persistence} and {@code config}
 * packages, so all of them run in the launcher's process. Outside the reach: the capabilities' jars, the
 * kernel, the JDBC driver and connection pool, the JDK, and the classes an operator names for the host parts.
 * Their own logging is not scanned.
 *
 * <p>The scan reads source text, not types: a name declared as a throwable type anywhere in a file is a
 * throwable name in that file, and a log call may pass such a name only as the receiver of
 * {@code getClass().getName()}.
 */
@DisplayName("Launcher sources: foreign text is logged only through LauncherLog")
class LauncherLogSourcesTest {

    private static final Path MAIN = Path.of("src", "main", "java");

    /** A violation the code is allowed to keep, by file and by a snippet of the statement. */
    private record Allowed(String file, String snippet, String reason) {
    }

    private static final List<Allowed> ALLOWED = List.of(
            new Allowed("eu/exeris/sku/identity/launcher/IdentitySkuApplication.java",
                    "System.err.println(\"Identity ended on a fatal VM error (\" + fatal.getClass().getName() + \")\")",
                    "the class name of a VM error, written when no logger can be trusted to run"));

    /** What the scan found: where, what rule, and the statement. */
    private record Finding(String file, int line, String rule, String statement) {
        @Override
        public String toString() {
            return file + ":" + line + ": " + rule + ": " + statement;
        }
    }

    private static final Pattern THROWABLE_DECLARATION = Pattern.compile(
            "\\b(?:Throwable|Exception|Error|[A-Z]\\w*(?:Exception|Error))\\s+(\\w+)\\s*[;=,)]");
    private static final Pattern CATCH_PARAMETER = Pattern.compile(
            "catch\\s*\\(\\s*(?:final\\s+)?[\\w.]+(?:\\s*\\|\\s*[\\w.]+)*\\s+(\\w+)\\s*\\)");
    private static final Pattern LOG_CALL = Pattern.compile("\\.\\s*(?:log|logp)\\s*\\(");
    private static final Pattern MESSAGE_CALL = Pattern.compile(
            "\\.\\s*(getMessage|getLocalizedMessage|getStackTrace|getCause|getSuppressed|toString|"
                    + "printStackTrace|fillInStackTrace|initCause)\\s*\\(");
    private static final Pattern CLASS_NAME_ONLY = Pattern.compile(
            "^\\s*\\)*\\s*\\.\\s*getClass\\s*\\(\\s*\\)\\s*\\.\\s*get(?:Simple)?Name\\s*\\(\\s*\\)");
    private static final Pattern STATE_ONLY = Pattern.compile("^\\s*\\.\\s*getSQLState\\s*\\(\\s*\\)");
    private static final Pattern PRINT_STACK = Pattern.compile("\\bprintStackTrace\\b");
    private static final Pattern STANDARD_STREAM = Pattern.compile("\\bSystem\\s*\\.\\s*(out|err)\\b");
    private static final Pattern STREAM_WRITE = Pattern.compile(
            "^\\s*\\.\\s*(print|println|printf|format|append|write)\\s*\\(");
    private static final Pattern OTHER_FRAMEWORK = Pattern.compile(
            "import\\s+(?:java\\.util\\.logging|org\\.slf4j|org\\.apache\\.logging|org\\.jboss\\.logging|"
                    + "ch\\.qos\\.logback)\\b");

    // --- the scan --------------------------------------------------------------------------------------

    /**
     * Replaces comments with spaces and the inside of string, text-block and character literals with 'x',
     * keeping every other character and every offset, so that structure can be read from the result and the
     * statement quoted from the original.
     */
    static String mask(String source) {
        StringBuilder out = new StringBuilder(source);
        int i = 0;
        int n = source.length();
        while (i < n) {
            char c = source.charAt(i);
            if (source.startsWith("//", i)) {
                while (i < n && source.charAt(i) != '\n') {
                    out.setCharAt(i++, ' ');
                }
            } else if (source.startsWith("/*", i)) {
                int end = source.indexOf("*/", i + 2);
                end = end < 0 ? n : end + 2;
                for (; i < end; i++) {
                    if (source.charAt(i) != '\n') {
                        out.setCharAt(i, ' ');
                    }
                }
            } else if (source.startsWith("\"\"\"", i)) {
                int end = source.indexOf("\"\"\"", i + 3);
                end = end < 0 ? n : end;
                for (int k = i + 3; k < end; k++) {
                    if (source.charAt(k) != '\n') {
                        out.setCharAt(k, 'x');
                    }
                }
                i = Math.min(n, end + 3);
            } else if (c == '"' || c == '\'') {
                int k = i + 1;
                while (k < n && source.charAt(k) != c && source.charAt(k) != '\n') {
                    if (source.charAt(k) == '\\') {
                        out.setCharAt(k++, 'x');
                    }
                    if (k < n) {
                        out.setCharAt(k++, 'x');
                    }
                }
                i = k + 1;
            } else {
                i++;
            }
        }
        return out.toString();
    }

    /** The offset just after the parenthesis that closes the one opened at {@code open}, in masked text. */
    private static int closing(String masked, int open) {
        int depth = 0;
        for (int i = open; i < masked.length(); i++) {
            char c = masked.charAt(i);
            if (c == '(') {
                depth++;
            } else if (c == ')' && --depth == 0) {
                return i + 1;
            }
        }
        return masked.length();
    }

    private static int lineOf(String text, int offset) {
        int line = 1;
        for (int i = 0; i < offset && i < text.length(); i++) {
            if (text.charAt(i) == '\n') {
                line++;
            }
        }
        return line;
    }

    private static String compact(String text) {
        return text.replaceAll("\\s+", " ").strip();
    }

    /** Every violation under the root, before the allow-list is applied, and the number of log calls looked at. */
    private record Scan(List<Finding> findings, int directLogCalls, int helperCalls, int files) {
    }

    private static Scan scan(Path root) throws IOException {
        List<Finding> findings = new ArrayList<>();
        int direct = 0;
        int helper = 0;
        List<Path> files;
        try (Stream<Path> walk = Files.walk(root)) {
            files = walk.filter(f -> f.toString().endsWith(".java")).sorted().toList();
        }
        for (Path file : files) {
            String name = root.relativize(file).toString().replace('\\', '/');
            String source = Files.readString(file);
            String masked = mask(source);
            Set<String> throwables = new HashSet<>();
            for (Pattern declaration : List.of(THROWABLE_DECLARATION, CATCH_PARAMETER)) {
                Matcher m = declaration.matcher(masked);
                while (m.find()) {
                    throwables.add(m.group(1));
                }
            }
            Matcher framework = OTHER_FRAMEWORK.matcher(masked);
            while (framework.find()) {
                findings.add(new Finding(name, lineOf(source, framework.start()), "another logging framework",
                        compact(source.substring(framework.start(), framework.end()))));
            }
            Matcher stack = PRINT_STACK.matcher(masked);
            while (stack.find()) {
                findings.add(new Finding(name, lineOf(source, stack.start()), "printStackTrace",
                        compact(source.substring(stack.start(), Math.min(source.length(), stack.start() + 60)))));
            }
            Matcher stream = STANDARD_STREAM.matcher(masked);
            while (stream.find()) {
                findings.addAll(streamUse(name, source, masked, stream));
            }
            Matcher call = LOG_CALL.matcher(masked);
            while (call.find()) {
                int open = call.end() - 1;
                int close = closing(masked, open);
                String before = masked.substring(Math.max(0, call.start() - 40), call.start());
                if (before.stripTrailing().endsWith("LauncherLog")) {
                    helper++;
                    continue;
                }
                direct++;
                String arguments = masked.substring(open + 1, close - 1);
                String statement = compact(source.substring(open + 1, close - 1));
                int line = lineOf(source, call.start());
                findings.addAll(throwableUse(name, line, statement, arguments, throwables));
            }
        }
        return new Scan(findings, direct, helper, files.size());
    }

    private static List<Finding> throwableUse(String file, int line, String statement, String arguments,
                                              Set<String> throwables) {
        List<Finding> found = new ArrayList<>();
        Matcher member = MESSAGE_CALL.matcher(arguments);
        while (member.find()) {
            found.add(new Finding(file, line, "log call uses ." + member.group(1) + "()", statement));
        }
        for (String name : throwables) {
            Matcher use = Pattern.compile("(?<![\\w])" + Pattern.quote(name) + "(?![\\w])").matcher(arguments);
            while (use.find()) {
                String rest = arguments.substring(use.end());
                // A throwable may be named only to read its class name; a call such as rootCause(e) is read
                // through the closing parenthesis.
                if (!CLASS_NAME_ONLY.matcher(rest).find() && !STATE_ONLY.matcher(rest).find()) {
                    found.add(new Finding(file, line, "log call passes throwable '" + name + "'", statement));
                }
            }
        }
        return found;
    }

    private static List<Finding> streamUse(String file, String source, String masked, Matcher stream) {
        int line = lineOf(source, stream.start());
        String after = masked.substring(stream.end());
        Matcher write = STREAM_WRITE.matcher(after);
        if (!write.find()) {
            return List.of(new Finding(file, line, "standard stream used other than by a print call",
                    compact(source.substring(stream.start(), Math.min(source.length(), stream.end() + 40)))));
        }
        int open = stream.end() + write.end() - 1;
        int close = closing(masked, open);
        String argument = masked.substring(open + 1, close - 1).strip();
        String statement = compact(source.substring(stream.start(), close));
        boolean constant = argument.matches("\"x*\"");
        return constant ? List.of() : List.of(new Finding(file, line, "standard stream written with non-constant text",
                statement));
    }

    private record Judged(List<Finding> violations, List<Allowed> stale) {
    }

    private static Judged judge(Scan scan, List<Allowed> allowed) {
        List<Finding> violations = new ArrayList<>();
        Set<Allowed> used = new HashSet<>();
        for (Finding finding : scan.findings()) {
            Allowed match = allowed.stream().filter(a -> a.file().equals(finding.file())
                    && finding.statement().contains(a.snippet())).findFirst().orElse(null);
            if (match == null) {
                violations.add(finding);
            } else {
                used.add(match);
            }
        }
        List<Allowed> stale = allowed.stream().filter(a -> !used.contains(a)).toList();
        return new Judged(violations, stale);
    }

    // --- the real sources ------------------------------------------------------------------------------

    @Test
    @DisplayName("No source passes a throwable, its message or its text to a logger, prints a stack, or writes variable text to a standard stream")
    void sources() throws IOException {
        Scan scan = scan(MAIN);

        long onDisk;
        try (Stream<Path> walk = Files.walk(MAIN)) {
            onDisk = walk.filter(f -> f.toString().endsWith(".java")).count();
        }
        assertThat(scan.files()).as("sources scanned").isEqualTo((int) onDisk).isGreaterThanOrEqualTo(50);
        assertThat(scan.directLogCalls()).as("direct logger calls looked at").isGreaterThanOrEqualTo(25);
        assertThat(scan.helperCalls()).as("calls through LauncherLog").isGreaterThanOrEqualTo(8);

        Judged judged = judge(scan, ALLOWED);

        assertThat(judged.violations()).as("violations").isEmpty();
    }

    @Test
    @DisplayName("Every allow-list entry still matches a statement of the sources")
    void noStaleEntries() throws IOException {
        Judged judged = judge(scan(MAIN), ALLOWED);

        assertThat(judged.stale()).as("entries that match nothing").isEmpty();
    }

    @Test
    @DisplayName("LauncherLog is the only caller of the redaction")
    void helperIsTheOnlyRoute() throws IOException {
        List<String> callers = new ArrayList<>();
        try (Stream<Path> walk = Files.walk(MAIN)) {
            for (Path file : walk.filter(f -> f.toString().endsWith(".java")).sorted().toList()) {
                if (mask(Files.readString(file)).contains("LogRedaction.of(")) {
                    callers.add(file.getFileName().toString());
                }
            }
        }

        assertThat(callers).containsExactly("LauncherLog.java");
    }

    // --- controls: the scan can fail -------------------------------------------------------------------

    private static List<Finding> violationsOf(Path dir, String body) throws IOException {
        Files.writeString(dir.resolve("C.java"), "class C {\n  System.Logger LOG;\n  Throwable failure;\n  void m() {\n"
                + body + "\n  }\n}\n");
        return scan(dir).findings();
    }

    @Test
    @DisplayName("The scan reports each way of putting a throwable into a log call, in one line or several, on any receiver")
    void reportsThrowableUse(@TempDir Path dir) throws IOException {
        List<String> bodies = List.of(
                "try { } catch (RuntimeException e) { LOG.log(System.Logger.Level.ERROR, \"x\", e); }",
                "try { } catch (RuntimeException e) { LOG.log(System.Logger.Level.ERROR, \"x {0}\", e.getMessage()); }",
                "try { } catch (RuntimeException e) { LOG.log(System.Logger.Level.ERROR, \"x {0}\", e.getLocalizedMessage()); }",
                "try { } catch (RuntimeException e) { LOG.log(System.Logger.Level.ERROR, \"x {0}\", e.toString()); }",
                "try { } catch (RuntimeException e) { LOG.log(System.Logger.Level.ERROR, \"x {0}\", String.valueOf(e)); }",
                "try { } catch (RuntimeException | Error e) { LOG.log(System.Logger.Level.ERROR, \"x \" + e); }",
                "try { } catch (RuntimeException e) { LOG.log(System.Logger.Level.ERROR, \"x {0}\", e.getCause()); }",
                "try { } catch (RuntimeException e) {\n LOG.log(System.Logger.Level.ERROR,\n \"x {0}\",\n e.getMessage());\n }",
                "try { } catch (RuntimeException e) { System.getLogger(\"n\").log(System.Logger.Level.ERROR, \"x {0}\", e.getMessage()); }",
                "LOG.log(System.Logger.Level.ERROR, \"x {0}\", failure.getMessage());",
                "LOG.log(System.Logger.Level.ERROR, \"x {0}\", failure);",
                "LOG.log(System.Logger.Level.ERROR, \"x {0}\", this.failure);");
        for (String body : bodies) {
            Path sub = Files.createDirectories(dir.resolve("t" + bodies.indexOf(body)));
            assertThat(violationsOf(sub, body)).as(body).isNotEmpty();
        }
    }

    @Test
    @DisplayName("The scan reports printStackTrace, a variable text on a standard stream and another logging framework")
    void reportsOtherPaths(@TempDir Path dir) throws IOException {
        List<String> bodies = List.of(
                "try { } catch (RuntimeException e) { e.printStackTrace(); }",
                "System.err.println(\"a\" + failure.getClass().getName());",
                "System.out.println(failure);",
                "System.err.printf(\"%s\", \"x\" + 1);",
                "Object o = System.err;");
        for (String body : bodies) {
            Path sub = Files.createDirectories(dir.resolve("t" + bodies.indexOf(body)));
            assertThat(violationsOf(sub, body)).as(body).isNotEmpty();
        }
        Path sub = Files.createDirectories(dir.resolve("framework"));
        Files.writeString(sub.resolve("F.java"), "import java.util.logging.Logger;\nclass F { }\n");
        assertThat(scan(sub).findings()).extracting(Finding::rule).contains("another logging framework");
    }

    @Test
    @DisplayName("The scan accepts class names, SQLSTATEs, the helper and a constant standard-stream line, and ignores comments and literals")
    void acceptsTheDocumentedForms(@TempDir Path dir) throws IOException {
        List<String> bodies = List.of(
                "try { } catch (RuntimeException e) { LOG.log(System.Logger.Level.ERROR, \"x {0}\", e.getClass().getName()); }",
                "try { } catch (RuntimeException e) { LOG.log(System.Logger.Level.ERROR, \"x {0} {1}\", e.getClass().getName(), root(e).getClass().getName()); }",
                "try { } catch (java.sql.SQLException e) { LOG.log(System.Logger.Level.ERROR, \"x {0}\", e.getSQLState()); }",
                "try { } catch (RuntimeException e) { LauncherLog.log(LOG, System.Logger.Level.ERROR, \"x {0}\", new String[0], e.getMessage()); }",
                "System.err.println(\"Shutdown signal received, draining\");",
                "LOG.log(System.Logger.Level.ERROR, \"e.getMessage() is not called here\");",
                "// LOG.log(System.Logger.Level.ERROR, \"x\", failure.getMessage());",
                "/* System.err.println(failure); */ int unused = 0;",
                "String s = \"System.err.println(failure)\";");
        for (String body : bodies) {
            Path sub = Files.createDirectories(dir.resolve("t" + bodies.indexOf(body)));
            assertThat(violationsOf(sub, body)).as(body).isEmpty();
        }
    }

    @Test
    @DisplayName("An allow-list entry removes a finding, and an entry that matches nothing is reported as stale")
    void allowListAndStale(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("C.java"), "class C { void m(Throwable failure) { System.err.println(\"a\" + failure); } }\n");
        Scan scan = scan(dir);
        assertThat(scan.findings()).hasSize(1);

        Judged covered = judge(scan, List.of(new Allowed("C.java", "System.err.println(\"a\" + failure)", "control")));
        Judged unrelated = judge(scan, List.of(new Allowed("C.java", "no such statement", "control"),
                new Allowed("D.java", "System.err.println", "control")));

        assertThat(covered.violations()).isEmpty();
        assertThat(covered.stale()).isEmpty();
        assertThat(unrelated.violations()).hasSize(1);
        assertThat(unrelated.stale()).hasSize(2);
    }

    @Test
    @DisplayName("The scan counts the log calls it looks at, so a pattern that finds none cannot pass")
    void countsCalls(@TempDir Path dir) throws IOException {
        Files.writeString(dir.resolve("C.java"), "class C { System.Logger LOG; void m() {\n"
                + "LOG.log(System.Logger.Level.INFO, \"a\");\nLauncherLog.log(LOG, System.Logger.Level.INFO, \"b\", new String[0]);\n"
                + "System.getLogger(\"n\")\n .log(System.Logger.Level.INFO, \"c\");\n} }\n");

        Scan scan = scan(dir);

        assertThat(scan.directLogCalls()).isEqualTo(2);
        assertThat(scan.helperCalls()).isEqualTo(1);
        assertThat(scan.files()).isEqualTo(1);
    }
}
