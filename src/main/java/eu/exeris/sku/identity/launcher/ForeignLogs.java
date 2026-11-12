package eu.exeris.sku.identity.launcher;

import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Makes the logging framework of the JVM unable to write a configured secret, whichever library logs it.
 *
 * <p>The PostgreSQL driver, the kernel and the capabilities log through {@code java.util.logging}, directly
 * or through {@code System.Logger}, whose default backend is the same framework. They write before any
 * exception exists, so the redaction at the launcher's own log statements cannot see their text. This class
 * installs, at the start of every command, a wrapper around each handler that is attached to a logger, and
 * every record of a logger the launcher does not own is rewritten before the wrapped handler sees it:
 * <ul>
 *   <li>the message is formatted with its parameters and resource bundle, then passed through
 *       {@link LauncherLog#redacted} with the command's secrets; the rewritten record carries no parameters, so
 *       a handler formats nothing again;</li>
 *   <li>the attached throwable is dropped, because its message, its cause chain's messages and its
 *       suppressed exceptions' messages are text this class cannot see inside; the record's message ends
 *       with the throwable's class name and those of its causes instead, redacted like the rest.</li>
 * </ul>
 * Records of the launcher's own loggers (the package of this class) are passed on unchanged: every foreign
 * text they carry went through {@link LauncherLog} already.
 *
 * <p>Not covered: text a library writes to the standard streams itself; a handler attached to a logger
 * created after {@link #begin}; a logging configuration that is reset or reloaded afterwards; and the
 * content of a host part's own logging when it uses another backend.
 *
 * <h2>Concurrency</h2>
 *
 * <p>The secrets are an immutable snapshot, an array that is built privately, never modified after it has
 * been stored and never handed out, held in an {@link AtomicReference}. The launcher thread replaces the
 * snapshot as a whole ({@link #begin}, {@link #learn}); a logging thread reads the reference once per record
 * and uses that snapshot throughout. The store is a release and the read an acquire, so a reader that sees
 * a snapshot sees all of its elements, and an element is an immutable {@code String}. A record published
 * while a secret is being added is redacted with the old or the new snapshot, never a mixture; a record
 * logged before {@link #learn} returns can only be redacted with the secrets known when it was published,
 * so {@link #learn} is called before the value it names is used for anything.
 *
 * <p>The logging path of the wrapper ({@code publish}, {@code flush}, {@code close}, {@code isLoggable}) never
 * throws and never calls itself: a record published while the same thread is already
 * inside the wrapper (a handler that logs from {@code publish}) is dropped, and any failure while rewriting
 * a record publishes a record that says only that it was withheld.
 */
final class ForeignLogs {

    /** Loggers whose names start with this are the launcher's own. */
    static final String OWNED_PREFIX = ForeignLogs.class.getPackageName();

    private static final AtomicReference<String[]> SECRETS = new AtomicReference<>(new String[0]);
    private static final String WITHHELD_RECORD = "(log record withheld)";
    private static final int MAXIMUM_CAUSES = 16;

    private ForeignLogs() {
    }

    /**
     * Starts a command: replaces the secrets with the given ones and installs the wrappers. Safe to call
     * again, in which case the wrappers already in place are kept.
     *
     * @param secrets the values that must never be written; may be empty
     */
    static void begin(String... secrets) {
        SECRETS.set(secrets.clone());
        install();
    }

    /**
     * Adds a secret that became known after {@link #begin}, such as a password read from a file. The
     * characters are copied into a {@code String} that cannot be zeroed and stays for the life of the process.
     *
     * @param secret the value; null or empty adds nothing
     */
    static void learn(char[] secret) {
        if (secret == null || secret.length == 0) {
            return;
        }
        String value = new String(secret);
        SECRETS.updateAndGet(known -> {
            for (String existing : known) {
                if (existing.equals(value)) {
                    return known;
                }
            }
            String[] more = Arrays.copyOf(known, known.length + 1);
            more[known.length] = value;
            return more;
        });
    }

    private static synchronized void install() {
        java.util.logging.LogManager manager = java.util.logging.LogManager.getLogManager();
        wrapHandlersOf(manager.getLogger(""));
        for (String name : Collections.list(manager.getLoggerNames())) {
            wrapHandlersOf(manager.getLogger(name));
        }
    }

    private static void wrapHandlersOf(java.util.logging.Logger logger) {
        if (logger == null) {
            return;
        }
        java.util.logging.Handler[] handlers = logger.getHandlers();
        boolean pending = false;
        for (java.util.logging.Handler handler : handlers) {
            pending |= !(handler instanceof Redacting);
        }
        if (!pending) {
            return;
        }
        for (java.util.logging.Handler handler : handlers) {
            logger.removeHandler(handler);
        }
        for (java.util.logging.Handler handler : handlers) {
            logger.addHandler(handler instanceof Redacting ? handler : new Redacting(handler));
        }
    }

    /** Whether a record of this logger is written by the launcher itself. */
    static boolean owned(String loggerName) {
        return loggerName != null && (loggerName.equals(OWNED_PREFIX) || loggerName.startsWith(OWNED_PREFIX + "."));
    }

    /**
     * The record as the wrapped handler sees it: the formatted message, redacted, followed by the class
     * names of the throwable and its causes, redacted; without parameters and without a throwable.
     *
     * @param record  the record
     * @param secrets the secrets to withhold
     * @return a new record
     */
    static java.util.logging.LogRecord rewrite(java.util.logging.LogRecord record, String[] secrets) {
        String message = MESSAGES.formatMessage(record);
        StringBuilder text = new StringBuilder(message == null ? "" : message);
        Throwable thrown = record.getThrown();
        if (thrown != null) {
            text.append(" [").append(classNames(thrown)).append(']');
        }
        java.util.logging.LogRecord out = new java.util.logging.LogRecord(record.getLevel(),
                LauncherLog.redacted(text.toString(), secrets));
        copyIdentity(record, out);
        return out;
    }

    private static void copyIdentity(java.util.logging.LogRecord from, java.util.logging.LogRecord to) {
        to.setLoggerName(from.getLoggerName());
        to.setInstant(from.getInstant());
        to.setLongThreadID(from.getLongThreadID());
        to.setSequenceNumber(from.getSequenceNumber());
        to.setSourceClassName(from.getSourceClassName());
        to.setSourceMethodName(from.getSourceMethodName());
    }

    private static String classNames(Throwable thrown) {
        StringBuilder names = new StringBuilder();
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        int depth = 0;
        for (Throwable t = thrown; t != null && seen.add(t) && depth < MAXIMUM_CAUSES; t = t.getCause(), depth++) {
            names.append(depth == 0 ? "" : " caused by ").append(t.getClass().getName());
        }
        return names.toString();
    }

    /** Formats a message with its parameters and resource bundle; formats no record as a whole. */
    private static final java.util.logging.Formatter MESSAGES = new java.util.logging.Formatter() {
        @Override
        public String format(java.util.logging.LogRecord record) {
            return "";
        }
    };

    /** The wrapper: rewrites a foreign record, then lets the wrapped handler do what it always did. */
    static final class Redacting extends java.util.logging.Handler {

        private static final ThreadLocal<Boolean> INSIDE = new ThreadLocal<>();

        private final java.util.logging.Handler wrapped;

        Redacting(java.util.logging.Handler wrapped) {
            this.wrapped = wrapped;
        }

        @Override
        public void publish(java.util.logging.LogRecord record) {
            if (record == null || INSIDE.get() != null) {
                return;
            }
            INSIDE.set(Boolean.TRUE);
            try {
                if (wrapped.isLoggable(record)) {
                    wrapped.publish(owned(record.getLoggerName()) ? record : rewrite(record, SECRETS.get()));
                }
            } catch (RuntimeException | StackOverflowError failure) {
                withheld(record);
            } finally {
                INSIDE.remove();
            }
        }

        private void withheld(java.util.logging.LogRecord record) {
            try {
                java.util.logging.LogRecord out = new java.util.logging.LogRecord(record.getLevel(), WITHHELD_RECORD);
                out.setLoggerName(record.getLoggerName());
                wrapped.publish(out);
            } catch (RuntimeException | StackOverflowError ignored) { // NOPMD - nothing more can be reported
                // the wrapper never throws
            }
        }

        @Override
        public void flush() {
            try {
                wrapped.flush();
            } catch (RuntimeException ignored) { // NOPMD - the wrapper never throws
                // nothing to report
            }
        }

        @Override
        public void close() {
            try {
                wrapped.close();
            } catch (RuntimeException ignored) { // NOPMD - the wrapper never throws
                // nothing to report
            }
        }

        @Override
        public boolean isLoggable(java.util.logging.LogRecord record) {
            try {
                return wrapped.isLoggable(record);
            } catch (RuntimeException ignored) { // NOPMD - the wrapper never throws
                return false;
            }
        }

        // The configuration of the wrapper is the configuration of the wrapped handler: a level, filter,
        // formatter, encoding or error manager set on the handler a logger shows takes effect on the handler
        // that writes. The setters and getters report what the wrapped handler reports, including its refusal
        // of an argument; they are configuration calls, not part of the logging path.

        @Override
        public synchronized void setLevel(java.util.logging.Level level) {
            wrapped.setLevel(level);
        }

        @Override
        public synchronized java.util.logging.Level getLevel() {
            return wrapped.getLevel();
        }

        @Override
        public synchronized void setFilter(java.util.logging.Filter filter) {
            wrapped.setFilter(filter);
        }

        @Override
        public synchronized java.util.logging.Filter getFilter() {
            return wrapped.getFilter();
        }

        @Override
        public synchronized void setFormatter(java.util.logging.Formatter formatter) {
            wrapped.setFormatter(formatter);
        }

        @Override
        public synchronized java.util.logging.Formatter getFormatter() {
            return wrapped.getFormatter();
        }

        @Override
        public synchronized void setEncoding(String encoding) throws java.io.UnsupportedEncodingException {
            wrapped.setEncoding(encoding);
        }

        @Override
        public synchronized String getEncoding() {
            return wrapped.getEncoding();
        }

        @Override
        public synchronized void setErrorManager(java.util.logging.ErrorManager manager) {
            wrapped.setErrorManager(manager);
        }

        @Override
        public synchronized java.util.logging.ErrorManager getErrorManager() {
            return wrapped.getErrorManager();
        }
    }
}
