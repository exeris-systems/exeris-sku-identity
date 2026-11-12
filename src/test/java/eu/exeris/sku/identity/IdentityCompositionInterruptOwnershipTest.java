package eu.exeris.sku.identity;

import eu.exeris.caps.serviceboundarycore.ServiceBoundaryCoreModule;
import eu.exeris.kernel.community.security.Argon2idPasswordEncoder;
import eu.exeris.kernel.spi.security.credentials.PasswordEncoderConfig;
import eu.exeris.sdk.composition.lifecycle.CapabilityLifecycleHooks;
import eu.exeris.sku.identity.config.IdentityConfig;
import eu.exeris.sku.identity.http.IdentityRoutes;
import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.JdbcTransactionalExecutor;
import eu.exeris.sku.identity.support.KnownDefect;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.RecordingNotificationDispatcher;
import eu.exeris.sku.identity.support.TestConfig;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.text.MessageFormat;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Who owns the calling thread's interrupt flag across a drain that the watchdog interrupted. Every
 * interleaving is forced with latches: the drain proves that the watchdog has fired by observing its own
 * interrupt, or by seeing the watchdog thread end, and a third party interrupts the caller only when a latch
 * says so. The capabilities are recording doubles; there is no database and no kernel.
 */
@DisplayName("IdentityComposition drain: ownership of the interrupt flag")
class IdentityCompositionInterruptOwnershipTest {

    private static final String WATCHDOG = "identity-drain-watchdog";
    private static final long BOUND_SECONDS = 60;
    private static final Duration BUDGET = Duration.ofMillis(400);
    private static final Duration GENEROUS = Duration.ofSeconds(60);
    private static final List<String> TERMINATES = List.of("terminate:D", "terminate:C", "terminate:B", "terminate:A");

    private static IdentityComposition base;
    private static Constructor<IdentityComposition> constructor;
    private static ServiceBoundaryCoreModule boundary;
    private static Method drainWithin;

    @BeforeAll
    static void assemble() throws Exception {
        PostgresSupport.Database unused = new PostgresSupport.Database("jdbc:postgresql://127.0.0.1:1/unused", "u", "p",
                "jdbc:postgresql://127.0.0.1:1/unused", "u", "p");
        IdentityConfig config = TestConfig.load();
        boundary = ServiceBoundaryCoreModule.builder().strictRoutes(true).build();
        base = IdentityComposition.builder()
                .config(config)
                .routes(new IdentityRoutes(config))
                .serviceBoundary(boundary)
                .transactionalExecutor(new JdbcTransactionalExecutor(unused))
                .passwordEncoder(new Argon2idPasswordEncoder(new PasswordEncoderConfig(8_192, 1, 1, 32)))
                .notificationDispatcher(new RecordingNotificationDispatcher())
                .membershipDirectory(new InMemoryMembershipDirectory())
                .build();
        constructor = IdentityComposition.class.getDeclaredConstructor(ServiceBoundaryCoreModule.class, List.class,
                eu.exeris.caps.jwt.api.JwtAdmissionPolicy.class, eu.exeris.caps.jwt.api.JwtServiceBoundaryBinding.class,
                IdentityServices.class);
        constructor.setAccessible(true);
        drainWithin = IdentityComposition.class.getDeclaredMethod("drainWithin", CapabilityLifecycleHooks.class,
                Duration.class);
        drainWithin.setAccessible(true);
    }

    @BeforeEach
    void noWatchdogIsAlive() {
        Thread.interrupted();
        awaitNoWatchdog();
    }

    // ---- the doubles -------------------------------------------------------------------------------------

    @FunctionalInterface
    private interface Action {
        void run() throws Exception;
    }

    /** A capability double that records the interrupt flag each of its drains and terminates saw. */
    private static final class Cap implements CapabilityLifecycleHooks {
        final String name;
        final List<String> log;
        volatile Action onDrain = () -> { };
        volatile Action onTerminate = () -> { };
        final List<Duration> slices = new CopyOnWriteArrayList<>();
        final List<Boolean> flagSeenByDrain = new CopyOnWriteArrayList<>();
        final List<Boolean> flagSeenByTerminate = new CopyOnWriteArrayList<>();

        Cap(String name, List<String> log) {
            this.name = name;
            this.log = log;
        }

        @Override
        public void initialize() {
            log.add("initialize:" + name);
        }

        @Override
        public void ready() {
            log.add("ready:" + name);
        }

        @Override
        public void drain(Duration timeout) throws Exception {
            log.add("drain:" + name);
            slices.add(timeout);
            flagSeenByDrain.add(Thread.currentThread().isInterrupted());
            onDrain.run();
        }

        @Override
        public void terminate() {
            log.add("terminate:" + name);
            flagSeenByTerminate.add(Thread.currentThread().isInterrupted());
            try {
                onTerminate.run();
            } catch (RuntimeException | Error e) {
                throw e;
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    private static final class Fixture {
        final List<String> log = Collections.synchronizedList(new ArrayList<>());
        final List<Cap> caps = List.of(new Cap("A", log), new Cap("B", log), new Cap("C", log), new Cap("D", log));
        final IdentityComposition composition;

        Fixture() {
            try {
                composition = constructor.newInstance(boundary, new ArrayList<CapabilityLifecycleHooks>(caps),
                        base.jwtAdmissionPolicy(), base.jwtBinding(), base.services());
            } catch (ReflectiveOperationException e) {
                throw new AssertionError(e);
            }
        }

        Cap cap(String name) {
            return caps.stream().filter(c -> c.name.equals(name)).findFirst().orElseThrow();
        }

        List<String> entries(String kind) {
            synchronized (log) {
                return log.stream().filter(e -> e.startsWith(kind + ":")).toList();
            }
        }
    }

    /** Collects the composition's own log records. */
    private static final class Capture extends Handler implements AutoCloseable {
        final List<LogRecord> records = new CopyOnWriteArrayList<>();
        private final Logger logger = Logger.getLogger(IdentityComposition.class.getName());
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

        /** The warnings about a drain that ran, not those about the drains that were skipped. */
        List<String> ofRunDrains() {
            return warnings().stream().filter(w -> !w.contains("budget is used up")).toList();
        }

        List<String> warnings() {
            return records.stream().filter(r -> r.getLevel().intValue() >= Level.WARNING.intValue())
                    .map(r -> {
                        Object[] parameters = r.getParameters();
                        return parameters == null || parameters.length == 0
                                ? r.getMessage() : MessageFormat.format(r.getMessage(), parameters);
                    }).toList();
        }
    }

    /** What one call did on its own thread. */
    private record Ran(Throwable thrown, boolean flagAfter) {
    }

    private static Ran onThread(boolean flagOnEntry, Callable<?> action) throws Exception {
        Object[] box = new Object[2];
        Thread thread = new Thread(() -> {
            if (flagOnEntry) {
                Thread.currentThread().interrupt();
            }
            try {
                action.call();
            } catch (Throwable thrown) {
                box[0] = thrown;
            }
            box[1] = Thread.currentThread().isInterrupted();
        }, "caller-under-test");
        thread.setDaemon(true);
        thread.start();
        thread.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
        if (thread.isAlive()) {
            thread.interrupt();
            throw new AssertionError("the call did not return within " + BOUND_SECONDS + " s");
        }
        return new Ran((Throwable) box[0], (Boolean) box[1]);
    }

    private static Ran stopped(Fixture fixture, Duration budget, boolean flagOnEntry) throws Exception {
        fixture.composition.start();
        return onThread(flagOnEntry, () -> {
            fixture.composition.stop(budget);
            return null;
        });
    }

    // ---- forcing an interleaving ---------------------------------------------------------------------------

    /** The latches and the facts that order a drain, the watchdog and a third party. */
    private static final class Probe {
        /** The drain has begun; {@link #caller} and {@link #watchdog} are known. */
        final CountDownLatch started = new CountDownLatch(1);
        /** The watchdog's interrupt has been consumed, or the watchdog thread has ended. */
        final CountDownLatch observed = new CountDownLatch(1);
        /** The third party has interrupted the caller. */
        final CountDownLatch sent = new CountDownLatch(1);
        volatile Thread caller;
        volatile Thread watchdog;
        volatile long beganNanos;
        volatile Duration slice;

        void begin(Cap cap) {
            caller = Thread.currentThread();
            watchdog = findWatchdog();
            slice = cap.slices.get(cap.slices.size() - 1);
            beganNanos = System.nanoTime();
            started.countDown();
        }

        /** Fails the test as inconclusive when the third party was so late that the watchdog may have fired. */
        void requireBeforeTheDeadline() {
            long elapsed = System.nanoTime() - beganNanos;
            if (elapsed > slice.toNanos() / 2 || !watchdog.isAlive()) {
                throw new AssertionError("inconclusive: the third party interrupt was not clearly before the fire");
            }
        }

        /** Interrupts the caller once {@code trigger} has been counted down. */
        void interruptWhen(CountDownLatch trigger) {
            Thread thirdParty = new Thread(() -> {
                try {
                    if (trigger.await(BOUND_SECONDS, TimeUnit.SECONDS)) {
                        caller.interrupt();
                        sent.countDown();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }, "third-party");
            thirdParty.setDaemon(true);
            thirdParty.start();
        }
    }

    private static Thread findWatchdog() {
        List<Thread> found = Thread.getAllStackTraces().keySet().stream()
                .filter(t -> t.getName().equals(WATCHDOG) && t.isAlive()).toList();
        if (found.size() != 1) {
            throw new AssertionError("expected exactly one watchdog thread, found " + found.size());
        }
        return found.get(0);
    }

    /** Waits without ever reading or consuming the interrupt flag. */
    private static void spinUntil(CountDownLatch latch) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
        while (latch.getCount() > 0) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("a latch was not counted down");
            }
            Thread.onSpinWait();
        }
    }

    /** The watchdog thread ends only after it has fired, or after the drain has ended and cancelled it. */
    private static void spinUntilEnded(Thread thread) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
        while (thread.isAlive()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("the watchdog did not fire");
            }
            Thread.onSpinWait();
        }
    }

    private static void sleepsUntilInterrupted(Probe probe) {
        try {
            Thread.sleep(Duration.ofSeconds(120));
            throw new AssertionError("no interrupt arrived");
        } catch (InterruptedException interrupted) {
            probe.observed.countDown();
        }
    }

    /** How the drain waits for the watchdog. */
    private enum Wait {
        /** It does not wait. */
        NONE,
        /** It spins, never reading the flag, until the watchdog thread has ended: the interrupt is pending. */
        FIRE_SPIN,
        /** It sleeps until the watchdog interrupts it: the interrupt is consumed. */
        FIRE_SLEEP
    }

    /** How the drain ends. */
    private enum End {
        /** Clears the flag and returns. */
        CONSUMES_AND_RETURNS,
        /** Returns with the flag as it is. */
        KEEPS_AND_RETURNS,
        /** Blocks, so that a pending interrupt makes it throw InterruptedException, which clears the flag. */
        THROWS_IE_REAL,
        /** Throws InterruptedException without touching the flag. */
        THROWS_IE_MANUAL,
        /** Throws an exception with no InterruptedException in its chain, without touching the flag. */
        THROWS_OTHER
    }

    private static void finish(End end) throws Exception {
        switch (end) {
            case CONSUMES_AND_RETURNS -> Thread.interrupted();
            case KEEPS_AND_RETURNS -> { }
            case THROWS_IE_REAL -> {
                Thread.sleep(Duration.ofSeconds(5));
                throw new AssertionError("no interrupt was pending");
            }
            case THROWS_IE_MANUAL -> throw new InterruptedException("thrown by the drain");
            case THROWS_OTHER -> throw new IllegalStateException("thrown by the drain");
        }
    }

    private static Action script(Cap cap, Probe probe, Wait wait, End end) {
        return () -> {
            probe.begin(cap);
            switch (wait) {
                case NONE -> { }
                case FIRE_SPIN -> {
                    spinUntilEnded(probe.watchdog);
                    probe.observed.countDown();
                }
                case FIRE_SLEEP -> sleepsUntilInterrupted(probe);
            }
            finish(end);
        };
    }

    private static boolean allTrue(List<Boolean> flags) {
        return !flags.isEmpty() && flags.stream().allMatch(b -> b);
    }

    private static boolean noneTrue(List<Boolean> flags) {
        return flags.stream().noneMatch(b -> b);
    }

    private static long liveWatchdogs() {
        return Thread.getAllStackTraces().keySet().stream()
                .filter(t -> t.getName().equals(WATCHDOG) && t.isAlive()).count();
    }

    private static void awaitNoWatchdog() {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (liveWatchdogs() > 0 && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        assertThat(liveWatchdogs()).as("watchdog threads alive").isZero();
    }

    private static boolean callDrainWithin(Cap cap, Duration slice) throws Exception {
        try {
            return (boolean) drainWithin.invoke(null, cap, slice);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof Exception ex) {
                throw ex;
            }
            throw (Error) e.getCause();
        }
    }

    // ---- 1: the flag set on entry ----------------------------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @EnumSource(End.class)
    @DisplayName("1a. A flag set on entry, the watchdog never fires: it is set on return, and every drain and terminate sees it")
    void entryFlagSetWatchdogDoesNotFire(End end) throws Exception {
        Fixture fixture = new Fixture();
        Probe probe = new Probe();
        fixture.cap("D").onDrain = script(fixture.cap("D"), probe, Wait.NONE, end);

        Ran ran = stopped(fixture, GENEROUS, true);

        assertThat(ran.thrown()).isNull();
        assertThat(ran.flagAfter()).isTrue();
        assertThat(fixture.entries("drain")).containsExactly("drain:D", "drain:C", "drain:B", "drain:A");
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
        fixture.caps.stream().filter(c -> !c.name.equals("D")).forEach(cap ->
                assertThat(allTrue(cap.flagSeenByTerminate)).as("terminate " + cap.name).isTrue());
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(End.class)
    @DisplayName("1b. A flag set on entry, the watchdog fires while the flag is pending: it is set on return whatever the drain did")
    void entryFlagSetWatchdogFires(End end) throws Exception {
        Fixture fixture = new Fixture();
        Probe probe = new Probe();
        fixture.cap("D").onDrain = script(fixture.cap("D"), probe, Wait.FIRE_SPIN, end);

        Ran ran = stopped(fixture, BUDGET, true);

        assertThat(probe.observed.getCount()).as("the watchdog fired").isZero();
        assertThat(ran.thrown()).isNull();
        assertThat(ran.flagAfter()).isTrue();
        assertThat(fixture.entries("drain")).as("the later drains are skipped").containsExactly("drain:D");
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
        fixture.caps.stream().filter(c -> !c.name.equals("D")).forEach(cap ->
                assertThat(allTrue(cap.flagSeenByTerminate)).as("terminate " + cap.name).isTrue());
    }

    // ---- 2: flag clear on entry, the watchdog fires, no third party -----------------------------------------

    @ParameterizedTest(name = "{0}")
    @EnumSource(value = End.class, names = {"CONSUMES_AND_RETURNS", "THROWS_IE_MANUAL", "THROWS_OTHER"})
    @DisplayName("2a. The drain consumes the watchdog's interrupt: the flag is clear on return, the later drains are skipped and every terminate sees it clear")
    void watchdogInterruptConsumed(End end) throws Exception {
        Fixture fixture = new Fixture();
        Probe probe = new Probe();
        fixture.cap("D").onDrain = script(fixture.cap("D"), probe, Wait.FIRE_SLEEP, end);
        try (Capture capture = new Capture()) {
            Ran ran = stopped(fixture, BUDGET, false);

            assertThat(probe.observed.getCount()).as("the watchdog fired").isZero();
            assertThat(ran.thrown()).isNull();
            assertThat(ran.flagAfter()).isFalse();
            assertThat(fixture.entries("drain")).containsExactly("drain:D");
            assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
            fixture.caps.forEach(cap -> assertThat(noneTrue(cap.flagSeenByTerminate)).as(cap.name).isTrue());
            assertThat(capture.ofRunDrains()).hasSize(1);
            assertThat(capture.warnings()).hasSize(4);
        }
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(value = End.class, names = {"KEEPS_AND_RETURNS", "THROWS_OTHER"})
    @DisplayName("2b. The drain ignores the watchdog's interrupt: the flag is cleared on return, and no terminate sees it")
    void watchdogInterruptIgnored(End end) throws Exception {
        Fixture fixture = new Fixture();
        Probe probe = new Probe();
        fixture.cap("D").onDrain = script(fixture.cap("D"), probe, Wait.FIRE_SPIN, end);
        try (Capture capture = new Capture()) {
            Ran ran = stopped(fixture, BUDGET, false);

            assertThat(probe.observed.getCount()).as("the watchdog fired").isZero();
            assertThat(ran.thrown()).isNull();
            assertThat(ran.flagAfter()).isFalse();
            assertThat(fixture.entries("drain")).containsExactly("drain:D");
            assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
            fixture.caps.forEach(cap -> assertThat(noneTrue(cap.flagSeenByTerminate)).as(cap.name).isTrue());
            assertThat(capture.ofRunDrains()).hasSize(1);
            assertThat(capture.warnings()).hasSize(4);
        }
    }

    private static Throwable chainWithInterruptAt(int depth) {
        Throwable t = new InterruptedException("deep");
        for (int i = 0; i < depth; i++) {
            t = new IllegalStateException("wrapper " + (i + 1), t);
        }
        return t;
    }

    @ParameterizedTest(name = "InterruptedException at cause depth {0}")
    @ValueSource(ints = {1, 5, 31, 32, 40})
    @DisplayName("2c. The drain consumes the interrupt and throws it wrapped at any depth: the flag is clear on return")
    void wrappedConsumedInterrupt(int depth) throws Exception {
        Fixture fixture = new Fixture();
        Probe probe = new Probe();
        fixture.cap("D").onDrain = () -> {
            probe.begin(fixture.cap("D"));
            sleepsUntilInterrupted(probe);
            throw (Exception) chainWithInterruptAt(depth);
        };

        Ran ran = stopped(fixture, BUDGET, false);

        assertThat(ran.thrown()).isNull();
        assertThat(ran.flagAfter()).isFalse();
        fixture.caps.forEach(cap -> assertThat(noneTrue(cap.flagSeenByTerminate)).as(cap.name).isTrue());
    }

    /**
     * The usual idiom: catch the interrupt, restore the flag and wrap. The chain is read down to depth 31 and
     * not beyond, so whether the restored flag is cleared depends on how deep the interrupt sits.
     */
    @ParameterizedTest(name = "InterruptedException at cause depth {0}")
    @ValueSource(ints = {1, 5, 31})
    @KnownDefect("expected: the watchdog's interrupt, restored by the drain before it wraps the exception, is cleared"
            + " on return; actual: the chain carries an InterruptedException, so the flag is left set and reaches"
            + " the terminates (IdentityComposition.java drainWithin, 'consumed = ... || carriesInterrupt(thrown)')")
    @DisplayName("2d. The drain restores the watchdog's interrupt and wraps the InterruptedException within the chain limit: the flag is clear on return")
    void wrappedRestoredInterruptWithinTheChainLimit(int depth) throws Exception {
        assertRestoredWrapperLeavesTheFlagClear(depth);
    }

    @ParameterizedTest(name = "InterruptedException at cause depth {0}")
    @ValueSource(ints = {32, 40})
    @DisplayName("2e. The drain restores the watchdog's interrupt and wraps the InterruptedException beyond the chain limit: the flag is clear on return")
    void wrappedRestoredInterruptBeyondTheChainLimit(int depth) throws Exception {
        assertRestoredWrapperLeavesTheFlagClear(depth);
    }

    private static void assertRestoredWrapperLeavesTheFlagClear(int depth) throws Exception {
        Fixture fixture = new Fixture();
        Probe probe = new Probe();
        fixture.cap("D").onDrain = () -> {
            probe.begin(fixture.cap("D"));
            sleepsUntilInterrupted(probe);
            Thread.currentThread().interrupt();
            throw (Exception) chainWithInterruptAt(depth);
        };

        Ran ran = stopped(fixture, BUDGET, false);

        assertThat(ran.thrown()).isNull();
        assertThat(ran.flagAfter()).as("flag on return, depth " + depth).isFalse();
        fixture.caps.forEach(cap -> assertThat(noneTrue(cap.flagSeenByTerminate))
                .as("terminate " + cap.name + " saw the watchdog's interrupt, depth " + depth).isTrue());
    }

    @Test
    @KnownDefect("expected: an InterruptedException rethrown with the flag restored is the watchdog's own interrupt and"
            + " is cleared on return; actual: 'consumed' is true for any InterruptedException, so the flag stays set"
            + " and reaches the terminates (IdentityComposition.java drainWithin, catch InterruptedException)")
    @DisplayName("2f. The drain restores the flag and rethrows the InterruptedException it caught: the flag is clear on return")
    void restoredFlagAndRethrownInterrupt() throws Exception {
        Fixture fixture = new Fixture();
        Probe probe = new Probe();
        fixture.cap("D").onDrain = () -> {
            probe.begin(fixture.cap("D"));
            try {
                Thread.sleep(Duration.ofSeconds(120));
            } catch (InterruptedException e) {
                probe.observed.countDown();
                Thread.currentThread().interrupt();
                throw e;
            }
        };

        Ran ran = stopped(fixture, BUDGET, false);

        assertThat(ran.thrown()).isNull();
        assertThat(ran.flagAfter()).isFalse();
        fixture.caps.forEach(cap -> assertThat(noneTrue(cap.flagSeenByTerminate)).as(cap.name).isTrue());
    }

    @Test
    @DisplayName("2g. The drain restores the flag and returns: the flag is clear on return")
    void restoredFlagAndReturn() throws Exception {
        Fixture fixture = new Fixture();
        Probe probe = new Probe();
        fixture.cap("D").onDrain = () -> {
            probe.begin(fixture.cap("D"));
            sleepsUntilInterrupted(probe);
            Thread.currentThread().interrupt();
        };

        Ran ran = stopped(fixture, BUDGET, false);

        assertThat(ran.thrown()).isNull();
        assertThat(ran.flagAfter()).isFalse();
        fixture.caps.forEach(cap -> assertThat(noneTrue(cap.flagSeenByTerminate)).as(cap.name).isTrue());
    }

    // ---- 3: a third party interrupts before the fire ---------------------------------------------------------

    @ParameterizedTest(name = "{0}")
    @EnumSource(End.class)
    @DisplayName("3. A third party interrupts before the watchdog fires: the flag is set on return whatever the drain did, no InterruptedException reaches the caller of stop, and the terminates see the flag set")
    void thirdPartyBeforeTheFire(End end) throws Exception {
        Fixture fixture = new Fixture();
        Probe probe = new Probe();
        probe.interruptWhen(probe.started);
        fixture.cap("D").onDrain = () -> {
            probe.begin(fixture.cap("D"));
            spinUntil(probe.sent);
            probe.requireBeforeTheDeadline();
            spinUntilEnded(probe.watchdog);
            finish(end);
        };

        Ran ran = stopped(fixture, BUDGET, false);

        assertThat(ran.thrown()).isNull();
        assertThat(ran.flagAfter()).isTrue();
        assertThat(fixture.entries("drain")).containsExactly("drain:D");
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
        fixture.caps.forEach(cap -> assertThat(allTrue(cap.flagSeenByTerminate))
                .as("terminate " + cap.name + " sees the flag set").isTrue());
    }

    // ---- 4: a third party interrupts after the fire, the watchdog's interrupt already consumed -------------

    private static Action afterConsumedFire(Cap cap, Probe probe, End end) {
        return () -> {
            probe.begin(cap);
            sleepsUntilInterrupted(probe);
            spinUntil(probe.sent);
            finish(end);
        };
    }

    private static void assertKeptAfterConsumedFire(End end) throws Exception {
        Fixture fixture = new Fixture();
        Probe probe = new Probe();
        probe.interruptWhen(probe.observed);
        fixture.cap("D").onDrain = afterConsumedFire(fixture.cap("D"), probe, end);

        Ran ran = stopped(fixture, BUDGET, false);

        assertThat(ran.thrown()).isNull();
        assertThat(ran.flagAfter()).as("the third party's interrupt, sent after the watchdog's was consumed").isTrue();
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
    }

    @Test
    @DisplayName("4a. The watchdog's interrupt is consumed, then a third party interrupts and the drain throws InterruptedException without touching the flag: the flag is set on return")
    void afterConsumedFireDrainThrowsInterruptWithTheFlagSet() throws Exception {
        assertKeptAfterConsumedFire(End.THROWS_IE_MANUAL);
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(value = End.class, names = {"KEEPS_AND_RETURNS", "THROWS_OTHER"})
    @KnownDefect("expected: an interrupt that arrives after the drain consumed the watchdog's is kept (the Javadoc says"
            + " so); actual: the drain ends with the flag set, which the gate reads as 'not consumed', and the flag"
            + " is cleared (IdentityComposition.java drainWithin, 'consumed = !end.flagAtEnd()')")
    @DisplayName("4b. The watchdog's interrupt is consumed, then a third party interrupts and the drain returns or throws another exception: the flag is set on return")
    void afterConsumedFireDrainEndsWithTheFlagSet(End end) throws Exception {
        assertKeptAfterConsumedFire(end);
    }

    @Test
    @KnownDefect("expected: after the watchdog's interrupt was consumed, an InterruptedException can only come from"
            + " another source, and its interrupt is kept; actual: the exception is swallowed because the watchdog"
            + " fired, the drain's own sleep cleared the flag, and nothing restores it"
            + " (IdentityComposition.java drainWithin, catch InterruptedException)")
    @DisplayName("4c. The watchdog's interrupt is consumed, then a third party interrupts and the drain blocks and throws InterruptedException: the flag is set on return")
    void afterConsumedFireDrainBlocksAndIsInterrupted() throws Exception {
        assertKeptAfterConsumedFire(End.THROWS_IE_REAL);
    }

    // ---- 5: a third party interrupts after the fire, the watchdog's interrupt still pending ---------------

    private static void assertRequestLost(End end) throws Exception {
        Fixture fixture = new Fixture();
        Probe probe = new Probe();
        probe.interruptWhen(probe.observed);
        fixture.cap("D").onDrain = () -> {
            probe.begin(fixture.cap("D"));
            spinUntilEnded(probe.watchdog);
            probe.observed.countDown();
            spinUntil(probe.sent);
            finish(end);
        };

        Ran ran = stopped(fixture, BUDGET, false);

        assertThat(probe.sent.getCount()).as("the third party interrupted").isZero();
        assertThat(ran.thrown()).isNull();
        assertThat(ran.flagAfter()).as("characterisation: the request coalesced with the watchdog's and is gone").isFalse();
        fixture.caps.forEach(cap -> assertThat(noneTrue(cap.flagSeenByTerminate)).as(cap.name).isTrue());
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
    }

    @Test
    @DisplayName("5a. Characterisation: a third party interrupts while the watchdog's interrupt is pending and the drain returns: the flag is clear on return, the request is lost")
    void characterisationPendingCoalescedInterruptDrainReturns() throws Exception {
        assertRequestLost(End.KEEPS_AND_RETURNS);
    }

    @Test
    @DisplayName("5b. Characterisation: a third party interrupts while the watchdog's interrupt is pending and the drain blocks and throws InterruptedException: the flag is clear on return, the request is lost")
    void characterisationPendingCoalescedInterruptDrainThrowsInterrupt() throws Exception {
        assertRequestLost(End.THROWS_IE_REAL);
    }

    @Test
    @DisplayName("5c. Characterisation: a third party interrupts while the watchdog's interrupt is pending and the drain throws another exception: the flag is clear on return, the request is lost")
    void characterisationPendingCoalescedInterruptDrainThrowsOther() throws Exception {
        assertRequestLost(End.THROWS_OTHER);
    }

    // ---- 6: the watchdog never fires -------------------------------------------------------------------------

    @Test
    @DisplayName("6a. A third party interrupts a drain that does not consume it, the budget is generous: the flag is untouched, set on return, no warning")
    void noFireThirdPartyNotConsumed() throws Exception {
        Fixture fixture = new Fixture();
        Probe probe = new Probe();
        probe.interruptWhen(probe.started);
        fixture.cap("D").onDrain = () -> {
            probe.begin(fixture.cap("D"));
            spinUntil(probe.sent);
        };
        try (Capture capture = new Capture()) {
            Ran ran = stopped(fixture, GENEROUS, false);

            assertThat(ran.thrown()).isNull();
            assertThat(ran.flagAfter()).isTrue();
            assertThat(capture.warnings()).isEmpty();
            assertThat(fixture.entries("drain")).containsExactly("drain:D", "drain:C", "drain:B", "drain:A");
            assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
            assertThat(allTrue(fixture.cap("A").flagSeenByDrain)).isTrue();
        }
    }

    @Test
    @DisplayName("6b. A third party interrupts a drain that throws InterruptedException for it, the budget is generous: the exception is logged as a failed drain, the stop continues, and the flag is as the drain left it, clear")
    void noFireThirdPartyConsumedByTheDrain() throws Exception {
        Fixture fixture = new Fixture();
        Probe probe = new Probe();
        probe.interruptWhen(probe.started);
        fixture.cap("D").onDrain = () -> {
            probe.begin(fixture.cap("D"));
            spinUntil(probe.sent);
            finish(End.THROWS_IE_REAL);
        };
        try (Capture capture = new Capture()) {
            Ran ran = stopped(fixture, GENEROUS, false);

            assertThat(ran.thrown()).isNull();
            assertThat(capture.warnings()).hasSize(1);
            assertThat(capture.warnings().get(0)).contains("draining").contains(InterruptedException.class.getName());
            assertThat(fixture.entries("drain")).containsExactly("drain:D", "drain:C", "drain:B", "drain:A");
            assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
            assertThat(ran.flagAfter()).as("the drain consumed the interrupt; the Javadoc says the flag is untouched")
                    .isFalse();
        }
    }

    // ---- 9a: terminates that run with the flag set -----------------------------------------------------------

    @Test
    @DisplayName("9a. A kept interrupt reaches the terminates: one that blocks fails fast and is logged, the others still run, and the stop does not throw")
    void terminatesRunWithTheKeptFlag() throws Exception {
        Fixture fixture = new Fixture();
        Probe probe = new Probe();
        probe.interruptWhen(probe.started);
        fixture.cap("D").onDrain = () -> {
            probe.begin(fixture.cap("D"));
            spinUntil(probe.sent);
            probe.requireBeforeTheDeadline();
            spinUntilEnded(probe.watchdog);
        };
        fixture.cap("C").onTerminate = () -> Thread.sleep(Duration.ofSeconds(30));
        try (Capture capture = new Capture()) {
            Ran ran = stopped(fixture, BUDGET, false);

            assertThat(ran.thrown()).isNull();
            assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
            assertThat(fixture.cap("D").flagSeenByTerminate).containsExactly(true);
            assertThat(fixture.cap("C").flagSeenByTerminate).containsExactly(true);
            assertThat(fixture.cap("B").flagSeenByTerminate).as("the blocking terminate consumed the flag").containsExactly(false);
            assertThat(capture.warnings()).anyMatch(w -> w.contains("terminating") && w.contains("IllegalStateException"));
            assertThat(ran.flagAfter()).isFalse();
        }
    }

    // ---- 10: the Javadoc of drainFirst and drainWithin -------------------------------------------------------

    private static final ScopedValue<String> BINDING = ScopedValue.newInstance();
    private static final ThreadLocal<String> LOCAL = new ThreadLocal<>();

    @Nested
    @DisplayName("10. What the Javadoc of drainFirst and drainWithin states")
    class Javadoc {

        @Test
        @DisplayName("A drain runs on the calling thread, which keeps the bindings the thread carries")
        void drainRunsOnTheCallerWithItsBindings() throws Exception {
            Fixture fixture = new Fixture();
            AtomicReference<Thread> ranOn = new AtomicReference<>();
            AtomicReference<String> scoped = new AtomicReference<>();
            AtomicReference<String> local = new AtomicReference<>();
            fixture.cap("D").onDrain = () -> {
                ranOn.set(Thread.currentThread());
                scoped.set(BINDING.isBound() ? BINDING.get() : null);
                local.set(LOCAL.get());
            };
            fixture.composition.start();
            AtomicReference<Thread> caller = new AtomicReference<>();

            Ran ran = onThread(false, () -> {
                caller.set(Thread.currentThread());
                LOCAL.set("local");
                ScopedValue.where(BINDING, "scoped").run(() -> fixture.composition.stop(Duration.ofSeconds(5)));
                return null;
            });

            assertThat(ran.thrown()).isNull();
            assertThat(ranOn.get()).isSameAs(caller.get());
            assertThat(scoped.get()).isEqualTo("scoped");
            assertThat(local.get()).isEqualTo("local");
        }

        @Test
        @DisplayName("A watchdog interrupts the calling thread at the deadline, and the result is false exactly then")
        void watchdogInterruptsAtTheDeadline() throws Exception {
            Cap overrun = new Cap("X", Collections.synchronizedList(new ArrayList<>()));
            Probe probe = new Probe();
            overrun.onDrain = script(overrun, probe, Wait.FIRE_SLEEP, End.CONSUMES_AND_RETURNS);
            Cap quick = new Cap("Y", Collections.synchronizedList(new ArrayList<>()));

            Boolean[] results = new Boolean[2];
            Ran ran = onThread(false, () -> {
                long begin = System.nanoTime();
                results[0] = callDrainWithin(overrun, Duration.ofMillis(300));
                assertThat(System.nanoTime() - begin).isGreaterThanOrEqualTo(Duration.ofMillis(300).toNanos());
                results[1] = callDrainWithin(quick, Duration.ofSeconds(30));
                return null;
            });

            assertThat(ran.thrown()).isNull();
            assertThat(results).containsExactly(false, true);
        }

        @Test
        @DisplayName("It throws what the drain threw, unless the watchdog had fired when it threw the InterruptedException")
        void throwsWhatTheDrainThrew() throws Exception {
            Cap failing = new Cap("X", Collections.synchronizedList(new ArrayList<>()));
            failing.onDrain = () -> {
                throw new java.io.IOException("drain");
            };
            Cap interrupted = new Cap("Y", Collections.synchronizedList(new ArrayList<>()));
            interrupted.onDrain = () -> {
                throw new InterruptedException("not the watchdog's");
            };
            Cap fired = new Cap("Z", Collections.synchronizedList(new ArrayList<>()));
            Probe probe = new Probe();
            fired.onDrain = script(fired, probe, Wait.FIRE_SLEEP, End.THROWS_IE_MANUAL);

            Throwable[] thrown = new Throwable[3];
            Boolean[] result = new Boolean[1];
            Ran ran = onThread(false, () -> {
                for (int i = 0; i < 2; i++) {
                    try {
                        callDrainWithin(i == 0 ? failing : interrupted, Duration.ofSeconds(30));
                    } catch (Exception e) {
                        thrown[i] = e;
                    }
                }
                result[0] = callDrainWithin(fired, Duration.ofMillis(300));
                return null;
            });

            assertThat(ran.thrown()).isNull();
            assertThat(thrown[0]).isInstanceOf(java.io.IOException.class);
            assertThat(thrown[1]).isInstanceOf(InterruptedException.class).hasMessage("not the watchdog's");
            assertThat(result[0]).as("the InterruptedException thrown after the fire is swallowed").isFalse();
        }

        @Test
        @DisplayName("The interrupt flag the thread entered with is set again on return, from every kind of ending")
        void entryFlagIsSetAgain() throws Exception {
            for (End end : End.values()) {
                for (Wait wait : new Wait[] {Wait.NONE, Wait.FIRE_SPIN}) {
                    Cap cap = new Cap("X", Collections.synchronizedList(new ArrayList<>()));
                    Probe probe = new Probe();
                    cap.onDrain = script(cap, probe, wait, end);

                    Ran ran = onThread(true, () -> {
                        try {
                            callDrainWithin(cap, Duration.ofMillis(300));
                        } catch (InterruptedException | IllegalStateException expected) {
                            // the drain's own exceptions are not what is under test
                        }
                        return null;
                    });

                    assertThat(ran.thrown()).as(end + " " + wait).isNull();
                    assertThat(ran.flagAfter()).as(end + " " + wait).isTrue();
                }
            }
        }

        @Test
        @DisplayName("Each abandoned drain is logged once at WARNING by the class of the capability, and a drain after the budget is used up is skipped and logged")
        void abandonedAndSkippedAreLogged() throws Exception {
            Fixture fixture = new Fixture();
            Probe probe = new Probe();
            fixture.cap("D").onDrain = script(fixture.cap("D"), probe, Wait.FIRE_SLEEP, End.CONSUMES_AND_RETURNS);
            try (Capture capture = new Capture()) {
                Ran ran = stopped(fixture, BUDGET, false);

                assertThat(ran.thrown()).isNull();
                assertThat(capture.ofRunDrains()).hasSize(1);
                assertThat(capture.ofRunDrains().get(0)).contains(Cap.class.getName());
                assertThat(capture.warnings()).as("one for the abandoned drain, one per skipped drain").hasSize(4);
            }
        }

        @Test
        @KnownDefect("expected: an interrupt of another source is not cleared except where it cannot be told from the"
                + " watchdog's (drainFirst Javadoc); actual: it is cleared when it arrives after the drain consumed"
                + " the watchdog's interrupt and the drain returns, which the code could tell apart"
                + " (IdentityComposition.java drainWithin)")
        @DisplayName("An interrupt of another source is not cleared, except where it cannot be told from the watchdog's")
        void anotherSourceIsNotClearedWhereItCanBeTold() throws Exception {
            assertKeptAfterConsumedFire(End.KEEPS_AND_RETURNS);
        }

        @Test
        @KnownDefect("expected: an interrupt the watchdog delivered never reaches a terminate (drainFirst Javadoc);"
                + " actual: a drain that restores the flag and wraps the InterruptedException leaves it set"
                + " (IdentityComposition.java drainWithin, carriesInterrupt)")
        @DisplayName("An interrupt the watchdog delivered never reaches the next drain or any terminate")
        void watchdogInterruptNeverReachesATerminate() throws Exception {
            assertRestoredWrapperLeavesTheFlagClear(1);
        }

        @Test
        @DisplayName("The watchdog does not fire after the drain has ended: no interrupt of the drain's watchdog arrives after the call returned")
        void noLateInterrupt() throws Exception {
            Cap cap = new Cap("X", Collections.synchronizedList(new ArrayList<>()));
            cap.onDrain = () -> { };
            Ran ran = onThread(false, () -> {
                for (int i = 0; i < 200; i++) {
                    callDrainWithin(cap, Duration.ofMillis(1));
                    long until = System.nanoTime() + 2_000_000L;
                    while (System.nanoTime() < until) {
                        assertThat(Thread.currentThread().isInterrupted()).as("round " + i).isFalse();
                        Thread.onSpinWait();
                    }
                }
                return null;
            });
            assertThat(ran.thrown()).isNull();
            awaitNoWatchdog();
        }
    }

    // ---- 7 and 8: the gate under a race ----------------------------------------------------------------------

    private static void spinUntilNanos(long target) {
        while (System.nanoTime() < target) {
            Thread.onSpinWait();
        }
    }

    @Test
    @DisplayName("7. The fire never happens after the end of the drain: 5000 rounds that end the drain within 0.2 ms of the deadline, and no interrupt of that watchdog arrives after the call returned")
    void theGateClosesTheFire() throws Exception {
        int rounds = 5_000;
        List<String> violations = Collections.synchronizedList(new ArrayList<>());
        int[] fired = new int[1];
        Ran ran = onThread(false, () -> {
            Cap cap = new Cap("X", Collections.synchronizedList(new ArrayList<>()));
            Duration slice = Duration.ofMillis(1);
            for (int round = 0; round < rounds; round++) {
                long offset = ((round % 21) - 10) * 20_000L;
                long before = System.nanoTime();
                cap.onDrain = () -> spinUntilNanos(before + slice.toNanos() + offset);
                boolean completed = callDrainWithin(cap, slice);
                if (!completed) {
                    fired[0]++;
                }
                if (Thread.currentThread().isInterrupted()) {
                    violations.add("round " + round + ": the flag is set on return, completed=" + completed);
                    Thread.interrupted();
                }
                long until = System.nanoTime() + 1_000_000L;
                while (System.nanoTime() < until) {
                    if (Thread.currentThread().isInterrupted()) {
                        violations.add("round " + round + ": an interrupt arrived after the call returned, completed=" + completed);
                        Thread.interrupted();
                        break;
                    }
                    Thread.onSpinWait();
                }
            }
            return null;
        });

        assertThat(ran.thrown()).isNull();
        assertThat(violations).isEmpty();
        assertThat(fired[0]).as("rounds in which the watchdog fired").isBetween(rounds / 20, rounds - rounds / 20);
        awaitNoWatchdog();
        System.out.println("GATE-STRESS rounds=" + rounds + " watchdogFired=" + fired[0]);
    }

    /** Interrupts a thread at a time given to it, without being started again for each round. */
    private static final class Interrupter implements AutoCloseable {
        volatile long target;
        volatile Thread victim;
        volatile int armed;
        volatile int done;
        volatile long sentAt;
        volatile boolean closed;
        private final Thread thread = new Thread(() -> {
            int seen = 0;
            while (!closed) {
                if (armed != seen) {
                    seen = armed;
                    spinUntilNanos(target);
                    victim.interrupt();
                    sentAt = System.nanoTime();
                    done = seen;
                } else {
                    Thread.onSpinWait();
                }
            }
        }, "interrupter");

        Interrupter() {
            thread.setDaemon(true);
            thread.start();
        }

        @Override
        public void close() {
            closed = true;
        }
    }

    private record Tally(int rounds, int sentBeforeAnyFire, int violations, int keptNearTheFire, int lostNearTheFire,
                         int watchdogFired) {
    }

    @Test
    @DisplayName("8a. A third party interrupts within 0.2 ms of the fire, 2000 rounds, flag clear on entry: sent before the watchdog could fire means set on return; the rest are counted")
    void raceThirdPartyNearTheFireFlagClear() throws Exception {
        Tally tally = raceCounting(false, 2_000);
        System.out.println("RACE-CLEAR " + tally);
        assertThat(tally.violations()).as("rounds in which a request sent before the earliest possible fire was lost").isZero();
    }

    @Test
    @DisplayName("8b. A third party interrupts within 0.2 ms of the fire, 2000 rounds, flag set on entry: the flag is set on return in every round")
    void raceThirdPartyNearTheFireFlagSet() throws Exception {
        Tally tally = raceCounting(true, 2_000);
        System.out.println("RACE-SET " + tally);
        assertThat(tally.violations()).isZero();
    }

    private static Tally raceCounting(boolean flagOnEntry, int rounds) throws Exception {
        List<String> violations = Collections.synchronizedList(new ArrayList<>());
        int[] counts = new int[5];
        Ran ran = onThread(false, () -> {
            try (Interrupter interrupter = new Interrupter()) {
                Cap cap = new Cap("X", Collections.synchronizedList(new ArrayList<>()));
                long slice = Duration.ofMillis(2).toNanos();
                for (int round = 0; round < rounds; round++) {
                    int id = round + 1;
                    long offset = ((round % 21) - 10) * 20_000L;
                    cap.onDrain = () -> {
                        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
                        while (interrupter.done != id) {
                            if (System.nanoTime() > deadline) {
                                throw new AssertionError("the interrupter did not run");
                            }
                            Thread.onSpinWait();
                        }
                    };
                    if (flagOnEntry) {
                        Thread.currentThread().interrupt();
                    }
                    interrupter.victim = Thread.currentThread();
                    long before = System.nanoTime();
                    interrupter.target = before + slice + offset;
                    interrupter.armed = id;
                    boolean completed = callDrainWithin(cap, Duration.ofNanos(slice));
                    boolean flagAfter = Thread.interrupted();
                    boolean sentBeforeAnyFire = interrupter.sentAt < before + slice;
                    counts[0]++;
                    if (sentBeforeAnyFire) {
                        counts[1]++;
                    }
                    if (!completed) {
                        counts[4]++;
                    }
                    if (flagOnEntry || sentBeforeAnyFire) {
                        if (!flagAfter) {
                            violations.add("round " + round + ": request lost, sentBeforeAnyFire=" + sentBeforeAnyFire);
                        }
                    } else if (flagAfter) {
                        counts[2]++;
                    } else {
                        counts[3]++;
                    }
                }
            }
            return null;
        });
        assertThat(ran.thrown()).isNull();
        awaitNoWatchdog();
        return new Tally(counts[0], counts[1], violations.size(), counts[2], counts[3], counts[4]);
    }

    @Test
    @DisplayName("8c. No third party, 2000 rounds ending at the deadline: the watchdog's own interrupt is never visible to the next drain, to a terminate, or to the caller, flag clear or set on entry")
    void raceWithoutThirdParty() throws Exception {
        for (boolean flagOnEntry : new boolean[] {false, true}) {
            List<String> violations = Collections.synchronizedList(new ArrayList<>());
            Ran ran = onThread(false, () -> {
                for (int round = 0; round < 2_000; round++) {
                    Fixture fixture = new Fixture();
                    fixture.composition.start();
                    long offset = ((round % 21) - 10) * 20_000L;
                    Cap first = fixture.cap("D");
                    Cap next = fixture.cap("C");
                    first.onDrain = () -> spinUntilNanos(System.nanoTime()
                            + Math.max(0, first.slices.get(0).toNanos() + offset));
                    next.onDrain = () -> { };
                    if (flagOnEntry) {
                        Thread.currentThread().interrupt();
                    }
                    fixture.composition.stop(Duration.ofMillis(4));
                    boolean flagAfter = Thread.interrupted();
                    if (flagAfter != flagOnEntry) {
                        violations.add("round " + round + ": flag on return " + flagAfter);
                    }
                    for (Cap cap : fixture.caps) {
                        if (cap.flagSeenByTerminate.stream().anyMatch(seen -> seen != flagOnEntry)) {
                            violations.add("round " + round + ": terminate " + cap.name + " saw " + cap.flagSeenByTerminate);
                        }
                    }
                    if (!next.slices.isEmpty() && next.slices.get(0).compareTo(Duration.ofMillis(2)) >= 0
                            && next.flagSeenByDrain.stream().anyMatch(seen -> seen != flagOnEntry)) {
                        violations.add("round " + round + ": the next drain saw " + next.flagSeenByDrain);
                    }
                }
                return null;
            });
            assertThat(ran.thrown()).isNull();
            assertThat(violations).as("entry flag " + flagOnEntry).isEmpty();
        }
    }
}
