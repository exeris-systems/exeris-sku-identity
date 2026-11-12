package eu.exeris.sku.identity.launcher;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.ListResourceBundle;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Filter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.logging.StreamHandler;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every record of a logger the launcher does not own reaches a handler already rewritten: formatted,
 * redacted with the command's secrets, without parameters, without a throwable. The tests install a handler
 * of their own on the root logger before the command begins, as the JVM's console handler is, and restore the
 * logging state they found.
 */
@DisplayName("ForeignLogs: the records of other loggers reach the handlers redacted")
class ForeignLogsTest {

    static final String WITHHELD = LogRedaction.WITHHELD;

    private JulState state;
    private Capture capture;
    private final List<Logger> keep = new ArrayList<>();

    /** Records what reaches it, like a handler would write it. */
    static class Capture extends Handler {
        final List<LogRecord> records = new ArrayList<>();
        final AtomicInteger flushes = new AtomicInteger();
        final AtomicInteger closes = new AtomicInteger();

        Capture() {
            setLevel(Level.ALL);
        }

        @Override
        public synchronized void publish(LogRecord record) {
            if (isLoggable(record)) {
                records.add(record);
            }
        }

        @Override
        public void flush() {
            flushes.incrementAndGet();
        }

        @Override
        public void close() {
            closes.incrementAndGet();
        }

        synchronized List<String> messages() {
            return records.stream().map(LogRecord::getMessage).toList();
        }

        synchronized String only() {
            assertThat(records).as("records captured").hasSize(1);
            return records.get(0).getMessage();
        }
    }

    @BeforeEach
    void installCapture() {
        state = new JulState();
        capture = new Capture();
        state.replaceRootHandlers(capture);
    }

    @AfterEach
    void restore() {
        state.close();
        keep.clear();
    }

    /** A logger of its own that reaches the root handlers and logs at every level. */
    private Logger logger(String name) {
        Logger logger = Logger.getLogger(name + "." + SecretForms.lowerCaseMarker());
        logger.setLevel(Level.ALL);
        keep.add(logger);
        return logger;
    }

    private static String secret() {
        return SecretForms.marker();
    }

    // --- which loggers are covered ---------------------------------------------------------------------

    @Test
    @DisplayName("The PostgreSQL driver's logger, a kernel logger, the root logger and loggers created before and after begin are redacted")
    void foreignLoggersAreRedacted() {
        String secret = secret();
        Logger before = logger("third.party.before");
        ForeignLogs.begin(secret);
        Logger after = logger("third.party.after");
        Logger driver = Logger.getLogger("org.postgresql");
        Logger kernel = Logger.getLogger("eu.exeris.kernel.x");
        Logger root = Logger.getLogger("");
        List<Logger> all = List.of(driver, kernel, root, before, after);

        for (Logger logger : all) {
            logger.log(Level.SEVERE, "failed with " + secret + " here");
        }

        assertThat(capture.messages()).hasSize(all.size()).allSatisfy(message -> {
            assertThat(message).doesNotContain(secret).contains(WITHHELD);
        });
    }

    @Test
    @DisplayName("A handler attached to a logger that exists when the command begins is wrapped; one on a logger created afterwards is not, as the reference says")
    void documentedGap() throws IOException {
        String secret = secret();
        Logger existing = logger("with.own.handler.before");
        existing.setUseParentHandlers(false);
        Capture existingHandler = new Capture();
        existing.addHandler(existingHandler);
        ForeignLogs.begin(secret);
        Logger created = logger("with.own.handler.after");
        created.setUseParentHandlers(false);
        Capture createdHandler = new Capture();
        created.addHandler(createdHandler);

        existing.log(Level.SEVERE, "x " + secret);
        created.log(Level.SEVERE, "x " + secret);

        assertThat(existingHandler.only()).as("a logger that existed").doesNotContain(secret);
        assertThat(createdHandler.only()).as("a logger created after begin: not covered").contains(secret);
        assertThat(capture.records).as("nothing reached the root handler").isEmpty();
        assertThat(Files.readString(Path.of("docs", "reference", "launcher.md")))
                .contains("a handler attached to a logger that is created after the command started");
        ForeignLogs.begin(secret);
        created.log(Level.SEVERE, "again " + secret);
        assertThat(createdHandler.messages().get(1)).as("the next command wraps it").doesNotContain(secret);
    }

    @Test
    @DisplayName("A logger of the launcher's own package passes unchanged; a sibling name that only starts like it is rewritten")
    void ownedLoggersPassThrough() {
        String secret = secret();
        ForeignLogs.begin(secret);
        String owned = "eu.exeris.sku.identity.launcher";
        Logger exact = Logger.getLogger(owned);
        Logger child = Logger.getLogger(owned + ".Nested." + SecretForms.lowerCaseMarker());
        exact.setLevel(Level.ALL);
        child.setLevel(Level.ALL);
        keep.addAll(List.of(exact, child));

        exact.log(Level.WARNING, "own line " + secret);
        child.log(Level.WARNING, "own line {0}", secret);

        assertThat(capture.records).hasSize(2);
        assertThat(capture.records.get(0).getMessage()).isEqualTo("own line " + secret);
        assertThat(capture.records.get(1).getParameters()).containsExactly(secret);
        for (String lookalike : List.of(owned + "X", owned + "x.Nested", "eu.exeris.sku.identity", "eu.exeris.sku.identity.launche")) {
            Logger logger = Logger.getLogger(lookalike);
            logger.setLevel(Level.ALL);
            keep.add(logger);
            capture.records.clear();

            logger.log(Level.WARNING, "foreign " + secret);

            assertThat(capture.only()).as(lookalike).doesNotContain(secret);
        }
        assertThat(ForeignLogs.owned(null)).isFalse();
        assertThat(ForeignLogs.owned(owned)).isTrue();
        assertThat(ForeignLogs.owned(owned + ".A")).isTrue();
        assertThat(ForeignLogs.owned(owned + "X")).isFalse();
    }

    @Test
    @DisplayName("A placeholder already in a foreign message is not damaged by a secret that is a piece of it")
    void existingPlaceholderIsNotMangled() {
        ForeignLogs.begin("held");
        Logger logger = logger("third.party.placeholder");

        logger.log(Level.WARNING, "a " + WITHHELD + " b");

        assertThat(capture.only()).isEqualTo("a " + WITHHELD + " b");
    }

    // --- levels and filters ----------------------------------------------------------------------------

    @Test
    @DisplayName("FINEST to SEVERE honour the handler's level, and the level survives the rewrite")
    void levelsOfTheHandler() {
        ForeignLogs.begin(secret());
        Logger logger = logger("third.party.levels");
        List<Level> levels = List.of(Level.FINEST, Level.FINER, Level.FINE, Level.CONFIG, Level.INFO,
                Level.WARNING, Level.SEVERE);

        for (Level threshold : List.of(Level.ALL, Level.CONFIG, Level.INFO, Level.WARNING, Level.SEVERE, Level.OFF)) {
            capture.setLevel(threshold);
            capture.records.clear();

            for (Level level : levels) {
                logger.log(level, "m " + level);
            }

            List<Level> expected = levels.stream()
                    .filter(l -> threshold != Level.OFF && l.intValue() >= threshold.intValue()).toList();
            assertThat(capture.records).as("threshold " + threshold).extracting(LogRecord::getLevel)
                    .containsExactlyElementsOf(expected);
        }
    }

    @Test
    @DisplayName("The handler's filter decides which records are written, at every level")
    void filterOfTheHandler() {
        ForeignLogs.begin(secret());
        Logger logger = logger("third.party.filter");
        Filter onlyWarnings = record -> record.getLevel() == Level.WARNING;
        capture.setFilter(onlyWarnings);

        for (Level level : List.of(Level.FINEST, Level.FINE, Level.INFO, Level.WARNING, Level.SEVERE)) {
            logger.log(level, "m");
        }

        assertThat(capture.records).extracting(LogRecord::getLevel).containsExactly(Level.WARNING);
    }

    // --- what the message can be -----------------------------------------------------------------------

    private static final class ThrowingToString {
        @Override
        public String toString() {
            throw new IllegalStateException("toString failed");
        }
    }

    private static final class Bundle extends ListResourceBundle {
        private final String value;

        Bundle(String value) {
            this.value = value;
        }

        @Override
        protected Object[][] getContents() {
            return new Object[][]{{"key.one", value}};
        }
    }

    @Test
    @DisplayName("A secret in the message, in a {0} parameter, split between the message and a parameter, or in a resource bundle is withheld")
    void secretInTheMessageForms() {
        String secret = secret();
        ForeignLogs.begin(secret);
        Logger logger = logger("third.party.forms");

        logger.log(Level.WARNING, "in the message " + secret);
        logger.log(Level.WARNING, "in a parameter {0}", secret);
        logger.log(Level.WARNING, "in a parameter {1} and {0}", new Object[]{"a", secret});
        logger.log(Level.WARNING, "split " + secret.substring(0, 9) + "{0}", secret.substring(9));
        LogRecord keyed = new LogRecord(Level.WARNING, "key.one");
        keyed.setResourceBundle(new Bundle("from the bundle " + secret));
        keyed.setLoggerName(logger.getName());
        logger.log(keyed);

        assertThat(capture.messages()).hasSize(5).allSatisfy(message -> assertThat(message).doesNotContain(secret)
                .contains(WITHHELD));
        assertThat(capture.records).allSatisfy(record -> {
            assertThat(record.getParameters()).isNull();
            assertThat(record.getResourceBundle()).isNull();
        });
    }

    @Test
    @DisplayName("Braces and quotes without parameters, a malformed pattern with parameters, a parameter whose toString throws and a null message are handled without a leak or an exception")
    void awkwardMessages() {
        String secret = secret();
        ForeignLogs.begin(secret);
        Logger logger = logger("third.party.awkward");

        logger.log(Level.WARNING, "it's {not} a pattern {0 " + secret);
        logger.log(Level.WARNING, "it's {0 " + secret, "p");
        logger.log(Level.WARNING, "'{0}' " + secret, "p");
        logger.log(Level.WARNING, "p {0} " + secret, new ThrowingToString());
        logger.log(Level.WARNING, "p {0}", new Object[]{new ThrowingToString()});
        LogRecord empty = new LogRecord(Level.WARNING, null);
        empty.setLoggerName(logger.getName());
        logger.log(empty);

        assertThat(capture.messages()).hasSize(6).allSatisfy(message -> {
            assertThat(message).isNotNull().doesNotContain(secret);
        });
        assertThat(capture.messages().get(0)).contains(WITHHELD);
        assertThat(capture.messages().get(3)).contains(WITHHELD);
    }

    // --- what the throwable can be ---------------------------------------------------------------------

    private static final class Odd extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final String text;

        Odd(String text) {
            super("message of Odd");
            this.text = text;
        }

        @Override
        public String toString() {
            return "Odd text " + text;
        }

        @Override
        public String getLocalizedMessage() {
            return text;
        }
    }

    private static final class Refusing extends RuntimeException {
        private static final long serialVersionUID = 1L;

        @Override
        public String getMessage() {
            throw new IllegalStateException("getMessage failed");
        }

        @Override
        public String getLocalizedMessage() {
            throw new IllegalStateException("getLocalizedMessage failed");
        }

        @Override
        public String toString() {
            throw new IllegalStateException("toString failed");
        }
    }

    @Test
    @DisplayName("A secret in a throwable's message, its cause's, a suppressed one's or a custom toString is not written; the class names of the chain are")
    void throwableIsReducedToClassNames() {
        String secret = secret();
        ForeignLogs.begin(secret);
        Logger logger = logger("third.party.thrown");
        IllegalStateException top = new IllegalStateException("top " + secret, new java.io.IOException("cause " + secret));
        top.addSuppressed(new IllegalArgumentException("suppressed " + secret));
        Odd odd = new Odd(secret);
        odd.initCause(new java.sql.SQLException("jdbc " + secret, "08001"));

        logger.log(Level.SEVERE, "failed", top);
        logger.log(Level.SEVERE, "failed", odd);

        assertThat(capture.records).hasSize(2).allSatisfy(record -> {
            assertThat(record.getThrown()).isNull();
            assertThat(record.getMessage()).doesNotContain(secret);
        });
        assertThat(capture.messages().get(0)).contains("java.lang.IllegalStateException")
                .contains("caused by java.io.IOException");
        assertThat(capture.messages().get(1)).contains(Odd.class.getName()).contains("caused by java.sql.SQLException");
        assertThat(capture.messages().get(0)).as("a suppressed exception is not named either")
                .doesNotContain("IllegalArgumentException");
    }

    @Test
    @DisplayName("A cyclic cause chain terminates, a chain of 40 is cut at 16 names, and a throwable that refuses to give its message does not matter")
    void chainsAreBounded() {
        ForeignLogs.begin(secret());
        Logger logger = logger("third.party.chains");
        RuntimeException a = new RuntimeException();
        IllegalStateException b = new IllegalStateException();
        a.initCause(b);
        b.initCause(a);
        Throwable deep = new RuntimeException("0");
        for (int i = 1; i < 40; i++) {
            deep = new RuntimeException(String.valueOf(i), deep);
        }

        logger.log(Level.SEVERE, "cycle", a);
        logger.log(Level.SEVERE, "deep", deep);
        logger.log(Level.SEVERE, "refusing", new Refusing());

        assertThat(capture.messages()).hasSize(3);
        assertThat(capture.messages().get(0)).isEqualTo("cycle [java.lang.RuntimeException caused by "
                + "java.lang.IllegalStateException]");
        assertThat(capture.messages().get(1).split("caused by", -1)).hasSize(16);
        assertThat(capture.messages().get(2)).isEqualTo("refusing [" + Refusing.class.getName() + "]");
    }

    @Test
    @DisplayName("A throwable whose getCause throws makes the record the withheld one, not an exception for the caller")
    void causeThatThrows() {
        ForeignLogs.begin(secret());
        Logger logger = logger("third.party.badcause");
        RuntimeException bad = new RuntimeException() {
            private static final long serialVersionUID = 1L;

            @Override
            public synchronized Throwable getCause() {
                throw new IllegalStateException("getCause failed");
            }
        };

        logger.log(Level.SEVERE, "cause", bad);

        assertThat(capture.only()).isEqualTo("(log record withheld)");
    }

    @Test
    @DisplayName("A handler that formats the record itself writes neither the secrets of the throwable nor a stack frame")
    void endToEndWithAStreamHandler() {
        String secret = secret();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        StreamHandler stream = new StreamHandler(out, new SimpleFormatter());
        stream.setLevel(Level.ALL);
        state.replaceRootHandlers(stream);
        ForeignLogs.begin(secret);
        Logger logger = logger("third.party.stream");

        logger.log(Level.SEVERE, "failed {0}", new Object[]{secret});
        logger.log(Level.SEVERE, "failed " + secret,
                new RuntimeException("top " + secret, new IllegalStateException("cause " + secret)));
        stream.flush();

        String written = out.toString(StandardCharsets.UTF_8);
        assertThat(written).doesNotContain(secret).contains("failed " + WITHHELD)
                .contains("java.lang.RuntimeException caused by java.lang.IllegalStateException")
                .doesNotContain("\tat ").doesNotContain("Caused by");
    }

    // --- both front ends --------------------------------------------------------------------------------

    @Test
    @DisplayName("A record written through System.Logger, which the kernel uses, and one written through java.util.logging are both redacted")
    void systemLoggerAndJul() {
        String secret = secret();
        ForeignLogs.begin(secret);
        String name = "eu.exeris.kernel." + SecretForms.lowerCaseMarker();
        System.Logger system = System.getLogger(name);
        Logger jul = logger("third.party.both");

        system.log(System.Logger.Level.ERROR, "system " + secret);
        system.log(System.Logger.Level.WARNING, "system {0}", secret);
        system.log(System.Logger.Level.ERROR, "system with throwable " + secret, new RuntimeException("x " + secret));
        jul.log(Level.SEVERE, "jul " + secret);

        assertThat(capture.messages()).hasSize(4).allSatisfy(message -> assertThat(message).doesNotContain(secret));
        assertThat(capture.records).extracting(LogRecord::getThrown).containsOnlyNulls();
        assertThat(capture.messages().get(2)).contains("java.lang.RuntimeException");
    }

    // --- installation ----------------------------------------------------------------------------------

    @Test
    @DisplayName("begin called again does not wrap a wrapper: a record is written once, and a handler added meanwhile is wrapped in its place")
    void beginIsIdempotent() {
        String secret = secret();
        ForeignLogs.begin(secret);
        ForeignLogs.begin(secret);
        ForeignLogs.begin(secret);
        Logger root = Logger.getLogger("");
        Logger logger = logger("third.party.twice");

        logger.log(Level.SEVERE, "x " + secret);

        assertThat(root.getHandlers()).hasSize(1);
        assertThat(capture.only()).doesNotContain(secret);

        Capture second = new Capture();
        root.addHandler(second);
        ForeignLogs.begin(secret);
        capture.records.clear();

        logger.log(Level.SEVERE, "y " + secret);

        assertThat(root.getHandlers()).hasSize(2);
        assertThat(capture.only()).doesNotContain(secret);
        assertThat(second.only()).doesNotContain(secret);
    }

    @Test
    @DisplayName("flush and close of the installed handler reach the handler it wraps")
    void flushAndCloseReachTheWrappedHandler() {
        ForeignLogs.begin(secret());
        Handler installed = Logger.getLogger("").getHandlers()[0];

        installed.flush();
        installed.close();

        assertThat(installed).isNotSameAs(capture);
        assertThat(capture.flushes.get()).isEqualTo(1);
        assertThat(capture.closes.get()).isEqualTo(1);
    }

    private static final class Throwing extends Handler {
        private final Error error;
        private final RuntimeException failure;
        int calls;

        Throwing(RuntimeException failure, Error error) {
            this.failure = failure;
            this.error = error;
        }

        @Override
        public void publish(LogRecord record) {
            calls++;
            fail();
        }

        @Override
        public void flush() {
            fail();
        }

        @Override
        public void close() {
            fail();
        }

        private void fail() {
            if (failure != null) {
                throw failure;
            }
            throw error;
        }
    }

    @Test
    @DisplayName("A handler that throws on publish does not break the caller, and the record is offered once more as the withheld record")
    void throwingHandlerDoesNotBreakTheCaller() {
        Throwing throwing = new Throwing(new IllegalStateException("handler failed"), null);
        Throwing overflow = new Throwing(null, new StackOverflowError());
        for (Throwing handler : List.of(throwing, overflow)) {
            state.replaceRootHandlers(handler);
            ForeignLogs.begin(secret());
            Logger logger = logger("third.party.throws");

            logger.log(Level.SEVERE, "x");

            assertThat(handler.calls).as(handler.failure == null ? "error" : "exception").isEqualTo(2);
        }
    }

    @Test
    @DisplayName("flush of a handler that throws does not break the caller")
    void throwingFlush() {
        state.replaceRootHandlers(new Throwing(new IllegalStateException("flush failed"), null));
        ForeignLogs.begin(secret());

        Logger.getLogger("").getHandlers()[0].flush();
    }

    @Test
    @DisplayName("close of a handler that throws does not break the caller: the wrapper never throws")
    void throwingClose() {
        state.replaceRootHandlers(new Throwing(new IllegalStateException("close failed"), null));
        ForeignLogs.begin(secret());

        Logger.getLogger("").getHandlers()[0].close();
    }

    @Test
    @DisplayName("A handler that logs from publish is not called again for that record, however often it logs, and the first record is written once")
    void reentrantHandlerDoesNotRecurse() {
        Logger noisy = logger("third.party.noisy");
        List<String> seen = new ArrayList<>();
        Handler loud = new Handler() {
            @Override
            public void publish(LogRecord record) {
                seen.add(record.getMessage());
                noisy.log(Level.SEVERE, "published again");
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        loud.setLevel(Level.ALL);
        state.replaceRootHandlers(loud);
        ForeignLogs.begin(secret());

        noisy.log(Level.SEVERE, "first");
        noisy.log(Level.SEVERE, "second");

        assertThat(seen).containsExactly("first", "second");
    }

    // --- the cap ---------------------------------------------------------------------------------------

    @Test
    @DisplayName("Eight secrets are withheld each; a ninth makes the whole record (message withheld)")
    void moreThanEightSecrets() {
        List<String> secrets = new ArrayList<>();
        for (int i = 0; i < 9; i++) {
            secrets.add(secret());
        }
        Logger logger = logger("third.party.cap");

        ForeignLogs.begin(secrets.subList(0, 8).toArray(String[]::new));
        logger.log(Level.WARNING, "a " + secrets.get(0) + " b " + secrets.get(7) + " c");
        assertThat(capture.only()).isEqualTo("a " + WITHHELD + " b " + WITHHELD + " c");

        capture.records.clear();
        ForeignLogs.begin(secrets.toArray(String[]::new));
        logger.log(Level.WARNING, "a " + secrets.get(0) + " b");
        assertThat(capture.only()).isEqualTo("(message withheld)");

        capture.records.clear();
        ForeignLogs.begin(secrets.subList(0, 8).toArray(String[]::new));
        ForeignLogs.learn(secrets.get(8).toCharArray());
        logger.log(Level.WARNING, "plain text with nothing in it");
        assertThat(capture.only()).as("learn past the cap").isEqualTo("(message withheld)");
    }
}
