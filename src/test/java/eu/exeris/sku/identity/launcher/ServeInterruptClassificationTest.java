package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.channels.ClosedByInterruptException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * How {@link IdentitySkuApplication#serve} treats an interrupt of the thread that calls it, and which
 * failures {@link IdentitySkuApplication#causedByInterrupt} takes for the interrupt's. Nothing here boots a
 * kernel: every case ends before the kernel would be asked to, which is part of what is checked.
 */
@DisplayName("serve and the classification of an interrupt")
class ServeInterruptClassificationTest {

    private static final long BOUND_SECONDS = 30;
    private static final String STOP_LINE = "Asked to stop before starting";

    /** Everything one {@code serve} call did. */
    private record Served(int status, boolean flagAfter, List<LogRecord> records, long millis) {

        List<String> messages() {
            return records.stream().map(r -> r.getLevel() + " " + r.getMessage()).toList();
        }

        List<LogRecord> atLeast(Level level) {
            return records.stream().filter(r -> r.getLevel().intValue() >= level.intValue()).toList();
        }
    }

    /** Collects the launcher's own log records. */
    private static final class Capture extends Handler implements AutoCloseable {
        private final List<LogRecord> records = new CopyOnWriteArrayList<>();
        private final Logger logger = Logger.getLogger(IdentitySkuApplication.class.getName());
        private final Level savedLevel = logger.getLevel();
        private final boolean savedParents = logger.getUseParentHandlers();

        Capture() {
            setLevel(Level.ALL);
            logger.setLevel(Level.ALL);
            logger.setUseParentHandlers(false);
            logger.addHandler(this);
        }

        @Override
        public void publish(LogRecord record) {
            records.add(record);
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
            logger.removeHandler(this);
            logger.setUseParentHandlers(savedParents);
            logger.setLevel(savedLevel);
        }
    }

    /**
     * Calls {@code serve} on a thread of its own, with the interrupt flag set or not on entry.
     */
    private static Served serve(Map<String, String> environment, boolean interruptedOnEntry) throws Exception {
        try (Capture capture = new Capture()) {
            Object[] result = new Object[2];
            long start = System.nanoTime();
            Thread thread = new Thread(() -> {
                if (interruptedOnEntry) {
                    Thread.currentThread().interrupt();
                }
                result[0] = IdentitySkuApplication.serve(environment);
                result[1] = Thread.currentThread().isInterrupted();
            }, "serve-under-test");
            thread.setDaemon(true);
            thread.start();
            thread.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
            if (thread.isAlive()) {
                thread.interrupt();
                throw new AssertionError("serve did not return within " + BOUND_SECONDS + " s");
            }
            return new Served((Integer) result[0], (Boolean) result[1], List.copyOf(capture.records),
                    TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start));
        }
    }

    private static Map<String, String> environmentFor(String url, String user, String password) {
        PostgresSupport.Database database = new PostgresSupport.Database(url, user, password, url, user, password);
        return ServeSupport.environment(database, 1, InMemoryMembershipDirectory.class.getName());
    }

    private static int closedPort() throws IOException {
        return LaunchedProcess.freePort();
    }

    // ---- the flag is set when serve is called ------------------------------------------------------------

    /** A server that counts the connections made to it and never answers one. */
    private static final class Listener implements AutoCloseable {
        final ServerSocket socket;
        final AtomicInteger connections = new AtomicInteger();
        final List<Socket> accepted = new CopyOnWriteArrayList<>();

        Listener() throws IOException {
            socket = new ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress());
            Thread acceptor = new Thread(() -> {
                try {
                    while (true) {
                        accepted.add(socket.accept());
                        connections.incrementAndGet();
                    }
                } catch (IOException closed) {
                    // the listener was closed
                }
            }, "listener-acceptor");
            acceptor.setDaemon(true);
            acceptor.start();
        }

        String url() {
            return "jdbc:postgresql://127.0.0.1:" + socket.getLocalPort() + "/identity";
        }

        @Override
        public void close() throws IOException {
            socket.close();
            for (Socket connection : accepted) {
                connection.close();
            }
        }
    }

    @Test
    @DisplayName("A flag set on entry ends with 0, one informational line, no failure line, the flag still set, and nothing built: no connection is made to the configured database")
    void flagOnEntryBuildsNothing() throws Exception {
        try (Listener database = new Listener()) {
            Map<String, String> environment = environmentFor(database.url(), "identity_service", "not-a-secret-value");

            Served served = serve(environment, true);

            assertThat(served.status()).isZero();
            assertThat(served.flagAfter()).as("the interrupt flag is still set").isTrue();
            assertThat(served.records()).as("exactly one line is logged: %s", served.messages()).hasSize(1);
            assertThat(served.records().get(0).getLevel()).isEqualTo(Level.INFO);
            assertThat(served.records().get(0).getMessage()).contains(STOP_LINE);
            assertThat(served.messages()).noneMatch(line -> line.toLowerCase().contains("fail"));
            assertThat(served.atLeast(Level.WARNING)).isEmpty();
            assertThat(served.millis()).as("quickly").isLessThan(5_000);
            Thread.sleep(200);
            assertThat(database.connections).as("connections made to the database").hasValue(0);
            assertThat(System.getProperty("exeris.persistence.password")).as("no kernel property was set").isNull();
        }
    }

    @Test
    @DisplayName("Without the flag the same unreachable database is status 69 with an error line, so the 0 above is the interrupt's and not the database's")
    void sameEnvironmentWithoutTheFlag() throws Exception {
        Map<String, String> environment = environmentFor("jdbc:postgresql://127.0.0.1:" + closedPort() + "/identity",
                "identity_service", "not-a-secret-value");

        Served served = serve(environment, false);

        assertThat(served.status()).isEqualTo(IdentitySkuApplication.EXIT_UNAVAILABLE);
        assertThat(served.atLeast(Level.SEVERE)).hasSize(1);
    }

    @Test
    @DisplayName("A configuration that is refused, with the flag set on entry: the documented 0, the refusal is not reported (a finding: the configuration error is hidden)")
    void badConfigurationWithTheFlagOnEntry() throws Exception {
        Served unflagged = serve(Map.of(), false);
        assertThat(unflagged.status()).isEqualTo(IdentitySkuApplication.EXIT_CONFIG);
        assertThat(unflagged.atLeast(Level.SEVERE)).isNotEmpty();

        Served flagged = serve(Map.of(), true);

        assertThat(flagged.status()).as("an interrupt delivered before serve is called ends it with 0").isZero();
        assertThat(flagged.atLeast(Level.WARNING)).as("and the refusal is not logged").isEmpty();
        assertThat(flagged.flagAfter()).isTrue();
    }

    @Test
    @DisplayName("A service role that is a superuser, with the flag set on entry: the documented 0, the role is not inspected (a finding: the wrong role is hidden)")
    void wrongRoleWithTheFlagOnEntry() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        Map<String, String> environment = ServeSupport.environment(new PostgresSupport.Database(database.ownerUrl(),
                database.ownerUser(), database.ownerPassword(), database.ownerUrl(), database.ownerUser(),
                database.ownerPassword()), 1, InMemoryMembershipDirectory.class.getName());

        Served unflagged = serve(environment, false);
        assertThat(unflagged.status()).isEqualTo(IdentitySkuApplication.EXIT_CONFIG);

        Served flagged = serve(environment, true);

        assertThat(flagged.status()).isZero();
        assertThat(flagged.atLeast(Level.WARNING)).isEmpty();
    }

    // ---- the flag is set while the database is being reached ----------------------------------------------

    @Test
    @DisplayName("An interrupt that arrives while the database is being reached, which then fails, is still status 69 with the failure logged: a real database failure is not turned into a stop")
    void interruptDuringAFailingDatabaseAttempt() throws Exception {
        try (Listener database = new Listener(); Capture capture = new Capture()) {
            Map<String, String> environment = environmentFor(database.url(), "identity_service", "not-a-secret-value");
            Object[] result = new Object[1];
            Thread thread = new Thread(() -> result[0] = IdentitySkuApplication.serve(environment), "serve-under-test");
            thread.setDaemon(true);
            thread.start();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(BOUND_SECONDS);
            while (database.connections.get() == 0 && System.nanoTime() < deadline) {
                Thread.sleep(5);
            }
            assertThat(database.connections.get()).as("the launcher reached for the database").isEqualTo(1);
            Thread.sleep(300);

            thread.interrupt();
            Thread.sleep(100);
            database.close();
            thread.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));

            assertThat(thread.isAlive()).isFalse();
            assertThat(result[0]).isEqualTo(IdentitySkuApplication.EXIT_UNAVAILABLE);
            assertThat(capture.records.stream().filter(r -> r.getLevel() == Level.SEVERE)).hasSize(1);
        }
    }

    // ---- causedByInterrupt -----------------------------------------------------------------------------

    /** Runs a check on a thread whose interrupt flag is set or not, and returns its answer and the flag after. */
    private static boolean[] classify(Throwable failure, boolean flag) throws Exception {
        boolean[] result = new boolean[2];
        Thread thread = new Thread(() -> {
            if (flag) {
                Thread.currentThread().interrupt();
            }
            result[0] = IdentitySkuApplication.causedByInterrupt(failure);
            result[1] = Thread.currentThread().isInterrupted();
        }, "classifier");
        thread.setDaemon(true);
        thread.start();
        thread.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
        assertThat(thread.isAlive()).as("the classification returned").isFalse();
        return result;
    }

    private static Throwable chain(Throwable root, int depth) {
        Throwable top = new IllegalStateException("layer " + depth, root);
        for (int i = depth - 1; i > 0; i--) {
            top = new RuntimeException("layer " + i, top);
        }
        return top;
    }

    @Test
    @DisplayName("With the flag set, an InterruptedException, an InterruptedIOException or a ClosedByInterruptException anywhere in the cause chain is a stop; the flag stays set")
    void interruptCausesWithTheFlagSet() throws Exception {
        List<Throwable> causes = List.of(new InterruptedException("x"), new InterruptedIOException("x"),
                new ClosedByInterruptException());
        for (Throwable cause : causes) {
            for (int depth : new int[] {0, 1, 2, 7}) {
                Throwable failure = depth == 0 ? cause : chain(cause, depth);
                boolean[] result = classify(failure, true);

                assertThat(result[0]).as("%s at depth %d", cause.getClass().getSimpleName(), depth).isTrue();
                assertThat(result[1]).as("the flag after").isTrue();
            }
        }
    }

    @Test
    @DisplayName("The same failures with the flag cleared are failures")
    void interruptCausesWithTheFlagCleared() throws Exception {
        for (Throwable cause : List.of(new InterruptedException("x"), new InterruptedIOException("x"),
                new ClosedByInterruptException())) {
            boolean[] result = classify(chain(cause, 3), false);

            assertThat(result[0]).as(cause.getClass().getSimpleName()).isFalse();
            assertThat(result[1]).isFalse();
        }
    }

    @Test
    @DisplayName("With the flag set, a failure that has no such cause is not guessed to be a stop: other exceptions, and an InterruptedException that is only suppressed")
    void flagWithoutAnInterruptCause() throws Exception {
        IllegalStateException suppressing = new IllegalStateException("with a suppressed interrupt");
        suppressing.addSuppressed(new InterruptedException("suppressed, not a cause"));
        List<Throwable> failures = List.of(new IllegalStateException("x"), new SQLException("x", "08001"),
                new IOException("x"), chain(new IOException("x", new SQLException("y")), 4), suppressing,
                new java.util.concurrent.CancellationException("x"), new Error("x"));
        for (Throwable failure : failures) {
            boolean[] result = classify(failure, true);

            assertThat(result[0]).as(failure.toString()).isFalse();
            assertThat(result[1]).as("the flag after").isTrue();
        }
        assertThat(classify(null, true)[0]).as("no failure at all").isFalse();
    }

    @Test
    @DisplayName("A cause chain with a cycle ends: with an interrupt cause in it the answer is true, without one it is false")
    void causeCycle() throws Exception {
        RuntimeException a = new RuntimeException("a");
        RuntimeException b = new RuntimeException("b");
        a.initCause(b);
        b.initCause(a);

        assertThat(classify(a, true)[0]).as("a cycle of two without an interrupt cause").isFalse();

        RuntimeException c = new RuntimeException("c");
        RuntimeException d = new RuntimeException("d", new InterruptedException("in the cycle"));
        c.initCause(d);
        InterruptedException cyclic = new InterruptedException("cyclic");
        cyclic.initCause(c);
        d.addSuppressed(cyclic);

        assertThat(classify(c, true)[0]).as("a chain that reaches an interrupt cause").isTrue();

        RuntimeException e = new RuntimeException("e");
        RuntimeException f = new RuntimeException("f");
        RuntimeException g = new RuntimeException("g");
        e.initCause(f);
        f.initCause(g);
        g.initCause(e);
        assertThat(classify(e, true)[0]).as("a cycle of three").isFalse();
    }

    // ---- what the reference says ------------------------------------------------------------------------

    @Test
    @DisplayName("The launcher reference states that an interrupt before serve is called ends with 0, that a signal never does, and names the failures that are not recognised")
    void referenceStatesTheRule() throws IOException {
        String reference = Files.readString(Path.of("docs", "reference", "launcher.md"));

        assertThat(reference).contains("for an interrupt delivered before `serve` is called");
        assertThat(reference).contains("A stop by signal never reports 0");
        assertThat(reference).contains("with no failure logged and the thread's interrupt flag still set");
        assertThat(reference).contains("an `InterruptedException`, an `InterruptedIOException` or a "
                + "`ClosedByInterruptException` is in the failure's cause chain");
        assertThat(reference).contains("does not guess");
    }

    // ---- defects ----------------------------------------------------------------------------------------

    /**
     * An {@link InterruptedIOException} is also what a socket timeout is: {@link SocketTimeoutException}
     * extends it. A timeout is a failure of the network, not an interrupt, and the flag being set for another
     * reason must not turn it into a stop.
     */
    @Nested
    @DisplayName("Known defects (run with -Didentity.knownDefects=true)")
    @EnabledIfSystemProperty(named = "identity.knownDefects", matches = "true")
    class KnownDefects {

        @Test
        @DisplayName("A socket timeout in the cause chain, with the flag set, is a failure of the network and not a stop")
        void socketTimeoutIsNotAStop() throws Exception {
            Throwable timeout = new RuntimeException("connect", new SQLException("The connection attempt failed.",
                    "08001", new SocketTimeoutException("Connect timed out")));

            assertThat(classify(timeout, true)[0]).isFalse();
        }
    }
}
