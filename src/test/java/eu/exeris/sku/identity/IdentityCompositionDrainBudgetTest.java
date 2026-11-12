package eu.exeris.sku.identity;

import eu.exeris.caps.serviceboundarycore.ServiceBoundaryCoreModule;
import eu.exeris.kernel.community.security.Argon2idPasswordEncoder;
import eu.exeris.kernel.spi.security.credentials.PasswordEncoderConfig;
import eu.exeris.sdk.composition.lifecycle.CapabilityLifecycleHooks;
import eu.exeris.sku.identity.config.IdentityConfig;
import eu.exeris.sku.identity.http.IdentityRoutes;
import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.JdbcTransactionalExecutor;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.RecordingNotificationDispatcher;
import eu.exeris.sku.identity.support.TestConfig;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.MessageFormat;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The time bound on the drains of {@link IdentityComposition}: one budget for all of them, the remaining
 * slice passed to each, a watchdog that interrupts the calling thread when the slice ends, and the calling
 * thread's interrupt flag. The capabilities are recording doubles; there is no database and no kernel.
 */
@DisplayName("IdentityComposition drain budget")
class IdentityCompositionDrainBudgetTest {

    private static final String WATCHDOG = "identity-drain-watchdog";
    private static final String TOSTRING_MARKER = "marker-from-tostring-9c41";
    private static final String MESSAGE_MARKER = "marker-from-exception-message-5d27";
    private static final long BOUND_SECONDS = 60;

    private static IdentityComposition base;
    private static Constructor<IdentityComposition> constructor;
    private static ServiceBoundaryCoreModule boundary;

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
    }

    @FunctionalInterface
    private interface Action {
        void run() throws Exception;
    }

    /** A capability double: records each call at its entry and can be made to wait or to fail. */
    private abstract static class Cap implements CapabilityLifecycleHooks {
        final String name;
        final List<String> log;
        volatile Action onInitialize = () -> { };
        volatile Action onReady = () -> { };
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
        public void initialize() throws Exception {
            log.add("initialize:" + name);
            onInitialize.run();
        }

        @Override
        public void ready() throws Exception {
            log.add("ready:" + name);
            onReady.run();
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

        @Override
        public String toString() {
            return TOSTRING_MARKER + "-" + name;
        }
    }

    private static final class CapA extends Cap {
        CapA(List<String> log) {
            super("A", log);
        }
    }

    private static final class CapB extends Cap {
        CapB(List<String> log) {
            super("B", log);
        }
    }

    private static final class CapC extends Cap {
        CapC(List<String> log) {
            super("C", log);
        }
    }

    private static final class CapD extends Cap {
        CapD(List<String> log) {
            super("D", log);
        }
    }

    private static final class Fixture {
        final List<String> log = Collections.synchronizedList(new ArrayList<>());
        final List<Cap> caps = List.of(new CapA(log), new CapB(log), new CapC(log), new CapD(log));
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

        List<String> snapshot() {
            synchronized (log) {
                return List.copyOf(log);
            }
        }

        List<String> entries(String kind) {
            return snapshot().stream().filter(e -> e.startsWith(kind + ":")).toList();
        }
    }

    private static final List<String> TERMINATES = List.of("terminate:D", "terminate:C", "terminate:B", "terminate:A");

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

        List<LogRecord> warnings() {
            return records.stream().filter(r -> r.getLevel().intValue() >= Level.WARNING.intValue()).toList();
        }

        /** Everything a record can carry: the formatted message, and the thrown with its message and cause. */
        static String text(LogRecord record) {
            StringBuilder text = new StringBuilder();
            Object[] parameters = record.getParameters();
            String message = record.getMessage();
            text.append(parameters == null || parameters.length == 0 ? message : MessageFormat.format(message, parameters));
            for (Throwable t = record.getThrown(); t != null; t = t.getCause()) {
                text.append(' ').append(t);
            }
            return text.toString();
        }

        List<String> warningTexts() {
            return warnings().stream().map(Capture::text).toList();
        }
    }

    /** What one call did on its own thread. */
    private record Ran(Throwable thrown, boolean flagAfter, long millis) {
    }

    /** Runs the action on a thread of its own, with the interrupt flag set or not on entry. */
    private static Ran onThread(boolean flagOnEntry, Callable<?> action) throws Exception {
        Object[] box = new Object[3];
        long begin = System.nanoTime();
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
            box[2] = System.nanoTime();
        }, "caller-under-test");
        thread.setDaemon(true);
        thread.start();
        thread.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
        if (thread.isAlive()) {
            thread.interrupt();
            throw new AssertionError("the call did not return within " + BOUND_SECONDS + " s");
        }
        return new Ran((Throwable) box[0], (Boolean) box[1], TimeUnit.NANOSECONDS.toMillis((Long) box[2] - begin));
    }

    private static Ran stopped(Fixture fixture, Duration budget, boolean flagOnEntry) throws Exception {
        fixture.composition.start();
        return onThread(flagOnEntry, () -> {
            fixture.composition.stop(budget);
            return null;
        });
    }

    /** A drain that waits for the interrupt, as a drain that honours its deadline does. */
    private static Action sleepsUntilInterrupted() {
        return () -> {
            try {
                Thread.sleep(Duration.ofSeconds(120));
            } catch (InterruptedException interrupted) {
                throw new InterruptedException(MESSAGE_MARKER);
            }
        };
    }

    private static void spinFor(Duration time) {
        long until = System.nanoTime() + time.toNanos();
        while (System.nanoTime() < until) {
            Thread.onSpinWait();
        }
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

    // ---- 1: a stop is bound by its budget ---------------------------------------------------------------

    @Test
    @DisplayName("A stop with a 2 s budget and a drain that sleeps 120 s returns in about 2 s, terminates every capability, and logs exactly one WARNING, naming the capability class and nothing the capability says")
    void overrunIsBoundedAndLoggedOnce() throws Exception {
        Fixture fixture = new Fixture();
        fixture.cap("A").onDrain = sleepsUntilInterrupted();
        try (Capture capture = new Capture()) {
            Ran ran = stopped(fixture, Duration.ofSeconds(2), false);

            assertThat(ran.thrown()).isNull();
            assertThat(ran.millis()).isBetween(1_800L, 5_000L);
            assertThat(fixture.entries("drain")).containsExactly("drain:D", "drain:C", "drain:B", "drain:A");
            assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
            assertThat(capture.warningTexts()).hasSize(1);
            assertThat(capture.warningTexts().get(0)).contains(CapA.class.getName());
            assertThat(capture.records).as("no record carries an exception").allMatch(r -> r.getThrown() == null);
            assertThat(capture.records.stream().map(Capture::text).toList())
                    .noneMatch(line -> line.contains(TOSTRING_MARKER) || line.contains(MESSAGE_MARKER));
            assertThat(ran.flagAfter()).as("the watchdog's interrupt is gone").isFalse();
        }
    }

    @Test
    @DisplayName("A drain that overruns the whole budget in the middle: the drains after it are skipped and each skip is logged by class, every terminate runs, and the stop ends at the budget")
    void overrunSkipsTheRest() throws Exception {
        Fixture fixture = new Fixture();
        fixture.cap("C").onDrain = sleepsUntilInterrupted();
        try (Capture capture = new Capture()) {
            Ran ran = stopped(fixture, Duration.ofSeconds(2), false);

            assertThat(ran.thrown()).isNull();
            assertThat(ran.millis()).isBetween(1_800L, 5_000L);
            assertThat(fixture.entries("drain")).containsExactly("drain:D", "drain:C");
            assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
            List<String> warnings = capture.warningTexts();
            assertThat(warnings).hasSize(3);
            assertThat(warnings.stream().filter(w -> w.contains(CapC.class.getName()))).hasSize(1);
            assertThat(warnings.stream().filter(w -> w.contains(CapB.class.getName()))).hasSize(1);
            assertThat(warnings.stream().filter(w -> w.contains(CapA.class.getName()))).hasSize(1);
            assertThat(warnings).noneMatch(line -> line.contains(TOSTRING_MARKER) || line.contains(MESSAGE_MARKER));
        }
    }

    // ---- 2: slices --------------------------------------------------------------------------------------

    @Test
    @DisplayName("A compliant drain that takes 300 ms shrinks the slice given to the next one; every slice is positive and no larger than what remained")
    void slicesShrink() throws Exception {
        Fixture fixture = new Fixture();
        Duration budget = Duration.ofSeconds(5);
        fixture.cap("D").onDrain = () -> Thread.sleep(300);

        Ran ran = stopped(fixture, budget, false);

        assertThat(ran.thrown()).isNull();
        Duration previous = budget;
        for (String name : List.of("D", "C", "B", "A")) {
            assertThat(fixture.cap(name).slices).as(name).hasSize(1);
            Duration slice = fixture.cap(name).slices.get(0);
            assertThat(slice).as(name).isPositive().isLessThanOrEqualTo(previous);
            previous = slice;
        }
        assertThat(fixture.cap("C").slices.get(0)).isLessThanOrEqualTo(fixture.cap("D").slices.get(0).minusMillis(290));
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
    }

    @Test
    @DisplayName("When a drain that does not watch its deadline uses up the budget, the later drains are skipped and logged by class, the overrun is logged once, every terminate runs without seeing the interrupt, and the caller gets it set")
    void exhaustedBudgetSkipsTheRest() throws Exception {
        Fixture fixture = new Fixture();
        fixture.cap("D").onDrain = () -> spinFor(Duration.ofMillis(900));
        try (Capture capture = new Capture()) {
            Ran ran = stopped(fixture, Duration.ofMillis(400), false);

            assertThat(ran.thrown()).isNull();
            assertThat(fixture.entries("drain")).containsExactly("drain:D");
            assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
            List<String> warnings = capture.warningTexts();
            assertThat(warnings).hasSize(4);
            for (Class<?> type : List.of(CapD.class, CapC.class, CapB.class, CapA.class)) {
                assertThat(warnings.stream().filter(w -> w.contains(type.getName()))).as(type.getSimpleName()).hasSize(1);
            }
            fixture.caps.forEach(cap -> assertThat(cap.flagSeenByTerminate).as(cap.name).containsExactly(false));
            assertThat(ran.flagAfter()).as("the watchdog's interrupt the drain left set is kept for the caller").isTrue();
        }
    }

    @Test
    @DisplayName("A zero or negative timeout drains nothing, logs each skip, terminates every capability and returns at once; documented by 'skipped if nothing remains'")
    void zeroAndNegativeTimeout() throws Exception {
        for (Duration budget : List.of(Duration.ZERO, Duration.ofSeconds(-1), Duration.ofNanos(Long.MIN_VALUE), Duration.ofDays(-36_500))) {
            Fixture fixture = new Fixture();
            try (Capture capture = new Capture()) {
                Ran ran = stopped(fixture, budget, false);

                assertThat(ran.thrown()).as(budget.toString()).isNull();
                assertThat(ran.millis()).as(budget.toString()).isLessThan(2_000);
                assertThat(fixture.entries("drain")).as(budget.toString()).isEmpty();
                assertThat(fixture.entries("terminate")).as(budget.toString()).containsExactlyElementsOf(TERMINATES);
                assertThat(capture.warnings()).as(budget.toString()).hasSize(4);
            }
        }
    }

    @Test
    @DisplayName("A timeout too long to count in nanoseconds does not overflow: every capability is drained with a positive slice, nothing hangs, and no watchdog is left")
    void veryLongTimeout() throws Exception {
        for (Duration budget : List.of(Duration.ofSeconds(Long.MAX_VALUE), Duration.ofNanos(Long.MAX_VALUE),
                Duration.ofDays(36_500))) {
            Fixture fixture = new Fixture();

            Ran ran = stopped(fixture, budget, false);

            assertThat(ran.thrown()).as(budget.toString()).isNull();
            assertThat(ran.millis()).isLessThan(5_000);
            assertThat(fixture.entries("drain")).containsExactly("drain:D", "drain:C", "drain:B", "drain:A");
            fixture.caps.forEach(cap -> assertThat(cap.slices.get(0)).as(cap.name).isPositive());
            assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
        }
        awaitNoWatchdog();
    }

    // ---- 3: a failed start --------------------------------------------------------------------------------

    @Test
    @DisplayName("The unwind of a start that failed in ready shares one 5 s budget however many drains overrun, then terminates everything")
    void failedReadyUnwindHasOneBudget() throws Exception {
        Fixture fixture = new Fixture();
        fixture.cap("D").onDrain = sleepsUntilInterrupted();
        fixture.cap("C").onDrain = sleepsUntilInterrupted();
        failReady(fixture, "B");

        Ran ran = onThread(false, () -> {
            fixture.composition.start();
            return null;
        });

        assertThat(ran.thrown()).isInstanceOf(IllegalStateException.class).hasMessage("ready B");
        assertThat(ran.millis()).as("one budget of 5 s, not one per drain").isBetween(4_800L, 8_000L);
        assertThat(fixture.entries("drain")).containsExactly("drain:D");
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
        assertThat(ran.flagAfter()).isFalse();
    }

    @Test
    @DisplayName("The unwind of a start that failed in initialize shares one 5 s budget however many drains overrun, then terminates the capabilities that entered initialize")
    void failedInitializeUnwindHasOneBudget() throws Exception {
        Fixture fixture = new Fixture();
        fixture.cap("B").onDrain = sleepsUntilInterrupted();
        fixture.cap("A").onDrain = sleepsUntilInterrupted();
        failInitialize(fixture, "C");

        Ran ran = onThread(false, () -> {
            fixture.composition.start();
            return null;
        });

        assertThat(ran.thrown()).isInstanceOf(IllegalStateException.class).hasMessage("initialize C");
        assertThat(ran.millis()).isBetween(4_800L, 8_000L);
        assertThat(fixture.entries("drain")).containsExactly("drain:B");
        assertThat(fixture.entries("terminate")).containsExactly("terminate:C", "terminate:B", "terminate:A");
    }

    private static void failReady(Fixture fixture, String name) {
        fixture.cap(name).onReady = () -> {
            throw new IllegalStateException("ready " + name);
        };
    }

    private static void failInitialize(Fixture fixture, String name) {
        fixture.cap(name).onInitialize = () -> {
            throw new IllegalStateException("initialize " + name);
        };
    }

    // ---- 4: the interrupt flag --------------------------------------------------------------------------

    @Test
    @DisplayName("A caller that enters with the flag set still has it set afterwards, and every drain and terminate sees it set on entry")
    void flagOnEntryIsPreserved() throws Exception {
        Fixture fixture = new Fixture();

        Ran ran = stopped(fixture, Duration.ofSeconds(5), true);

        assertThat(ran.thrown()).isNull();
        assertThat(ran.flagAfter()).isTrue();
        fixture.caps.forEach(cap -> {
            assertThat(cap.flagSeenByDrain).as("drain " + cap.name).containsExactly(true);
            assertThat(cap.flagSeenByTerminate).as("terminate " + cap.name).containsExactly(true);
        });
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
    }

    @Test
    @DisplayName("A caller that enters with the flag set and a drain that gives up at once on the interrupt: the failed drain is logged once, the stop still terminates everything and does not throw")
    void interruptibleDrainOnAFlaggedCallerDoesNotBreakTheStop() throws Exception {
        Fixture fixture = new Fixture();
        fixture.cap("D").onDrain = () -> Thread.sleep(Duration.ofSeconds(30));
        try (Capture capture = new Capture()) {
            Ran ran = stopped(fixture, Duration.ofSeconds(5), true);

            assertThat(ran.thrown()).isNull();
            assertThat(ran.millis()).as("D returned at once").isLessThan(3_000);
            assertThat(fixture.entries("drain")).containsExactly("drain:D", "drain:C", "drain:B", "drain:A");
            assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
            assertThat(capture.warnings()).hasSize(1);
        }
    }

    @Test
    @DisplayName("A watchdog interrupt never reaches a terminate, and the thread does not carry it out of the stop")
    void watchdogInterruptDoesNotReachTerminate() throws Exception {
        Fixture fixture = new Fixture();
        fixture.cap("D").onDrain = sleepsUntilInterrupted();
        fixture.caps.forEach(cap -> cap.onTerminate = () -> Thread.sleep(150));

        Ran ran = stopped(fixture, Duration.ofMillis(500), false);

        assertThat(ran.thrown()).isNull();
        fixture.caps.forEach(cap -> assertThat(cap.flagSeenByTerminate).as(cap.name).containsExactly(false));
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
        assertThat(ran.flagAfter()).isFalse();
    }

    @Test
    @DisplayName("A drain that returns as the watchdog fires, 2000 times over: the next drain and every terminate see no interrupt, and the caller has it set when the watchdog fired and a drain that never reads the flag ended with it, and clear otherwise")
    void raceWithNoFlagOnEntry() throws Exception {
        List<String> violations = Collections.synchronizedList(new ArrayList<>());
        Ran ran = onThread(false, () -> {
            for (int round = 0; round < 2_000; round++) {
                Fixture fixture = new Fixture();
                fixture.composition.start();
                long offsetNanos = ((round % 21) - 10) * 100_000L;
                boolean spin = round % 2 == 0;
                fixture.cap("D").onDrain = () -> {
                    Duration slice = fixture.cap("D").slices.get(0);
                    long until = System.nanoTime() + slice.toNanos() + offsetNanos;
                    if (spin) {
                        while (System.nanoTime() < until) {
                            Thread.onSpinWait();
                        }
                    } else {
                        long sleep = until - System.nanoTime();
                        if (sleep > 0) {
                            Thread.sleep(Duration.ofNanos(sleep));
                        }
                    }
                };
                boolean fired;
                try (Capture capture = new Capture()) {
                    fixture.composition.stop(Duration.ofMillis(3));
                    fired = capture.warningTexts().stream().anyMatch(w -> w.contains("overran"));
                }
                boolean flagAfter = Thread.interrupted();
                if (!fired && flagAfter) {
                    violations.add("round " + round + ": stray interrupt left on the caller, no watchdog fired");
                }
                if (fired && spin && !flagAfter) {
                    violations.add("round " + round + ": the interrupt a spinning drain ended with was not kept");
                }
                for (Cap cap : fixture.caps) {
                    // A later drain's own watchdog may fire inside a slice of a few microseconds, so only a
                    // drain with a slice that no scheduling delay explains can show a leak.
                    if (!cap.name.equals("D") && !cap.slices.isEmpty()
                            && cap.slices.get(0).compareTo(Duration.ofMillis(2)) >= 0
                            && cap.flagSeenByDrain.contains(true)) {
                        violations.add("round " + round + ": drain " + cap.name + " saw an interrupt");
                    }
                    if (cap.flagSeenByTerminate.contains(true)) {
                        violations.add("round " + round + ": terminate " + cap.name + " saw an interrupt");
                    }
                }
            }
            Thread.sleep(100);
            if (Thread.currentThread().isInterrupted()) {
                violations.add("a late interrupt arrived after the last round");
            }
            return null;
        });

        assertThat(ran.thrown()).isNull();
        assertThat(violations).isEmpty();
    }

    @Test
    @DisplayName("Drains that each block for 100 ms inside a 5 s budget are not interrupted by the watchdog of an earlier one: every drain completes its wait and sees no interrupt")
    void earlierWatchdogsDoNotInterruptLaterDrains() throws Exception {
        for (int round = 0; round < 20; round++) {
            Fixture fixture = new Fixture();
            AtomicBoolean interrupted = new AtomicBoolean();
            fixture.caps.forEach(cap -> cap.onDrain = () -> {
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    interrupted.set(true);
                    throw e;
                }
            });

            Ran ran = stopped(fixture, Duration.ofSeconds(5), false);

            assertThat(ran.thrown()).isNull();
            assertThat(interrupted).isFalse();
            fixture.caps.forEach(cap -> assertThat(cap.flagSeenByDrain).as(cap.name).containsExactly(false));
            assertThat(ran.flagAfter()).isFalse();
        }
    }

    @Test
    @DisplayName("With the flag set on entry, a drain that returns as the watchdog fires, 2000 times over, never costs the caller its flag")
    void raceWithTheFlagOnEntry() throws Exception {
        List<String> violations = Collections.synchronizedList(new ArrayList<>());
        Ran ran = onThread(true, () -> {
            for (int round = 0; round < 2_000; round++) {
                Fixture fixture = new Fixture();
                fixture.composition.start();
                long offsetNanos = ((round % 21) - 10) * 100_000L;
                fixture.cap("D").onDrain = () -> {
                    Duration slice = fixture.cap("D").slices.get(0);
                    spinFor(slice.plusNanos(offsetNanos));
                };
                fixture.composition.stop(Duration.ofMillis(3));
                if (!Thread.currentThread().isInterrupted()) {
                    violations.add("round " + round + ": the caller's own flag was lost");
                    Thread.currentThread().interrupt();
                }
            }
            return null;
        });

        assertThat(ran.thrown()).isNull();
        assertThat(violations).isEmpty();
        assertThat(ran.flagAfter()).isTrue();
    }

    // ---- 5: no thread leak ----------------------------------------------------------------------------------

    @Test
    @DisplayName("After 1000 normal stops, and after an overrun, no watchdog thread remains")
    void noWatchdogRemains() throws Exception {
        for (int i = 0; i < 1_000; i++) {
            Fixture fixture = new Fixture();
            fixture.composition.start();
            fixture.composition.stop(Duration.ofSeconds(30));
        }
        awaitNoWatchdog();

        Fixture overrun = new Fixture();
        overrun.cap("D").onDrain = sleepsUntilInterrupted();
        Ran ran = stopped(overrun, Duration.ofMillis(300), false);

        assertThat(ran.thrown()).isNull();
        awaitNoWatchdog();
    }

    // ---- 6: re-entry and concurrency --------------------------------------------------------------------------

    @Test
    @DisplayName("A drain that calls stop on its own composition does not deadlock: the call does nothing and the outer stop completes with each capability drained and terminated once")
    void drainCallsStop() throws Exception {
        Fixture fixture = new Fixture();
        AtomicBoolean returned = new AtomicBoolean();
        fixture.cap("C").onDrain = () -> {
            fixture.composition.stop(Duration.ofSeconds(1));
            returned.set(true);
        };

        Ran ran = stopped(fixture, Duration.ofSeconds(5), false);

        assertThat(ran.thrown()).isNull();
        assertThat(returned).isTrue();
        assertThat(fixture.entries("drain")).containsExactly("drain:D", "drain:C", "drain:B", "drain:A");
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
    }

    @Test
    @DisplayName("A drain that calls start or tryStart on its own composition is refused with IllegalStateException; that failure is logged and the unwind goes on")
    void drainCallsStart() throws Exception {
        Fixture fixture = new Fixture();
        List<Throwable> refusals = new CopyOnWriteArrayList<>();
        fixture.cap("D").onDrain = () -> {
            try {
                fixture.composition.start();
            } catch (IllegalStateException refused) {
                refusals.add(refused);
            }
            try {
                fixture.composition.tryStart();
            } catch (IllegalStateException refused) {
                refusals.add(refused);
            }
        };
        fixture.cap("C").onDrain = () -> fixture.composition.start();
        try (Capture capture = new Capture()) {
            Ran ran = stopped(fixture, Duration.ofSeconds(5), false);

            assertThat(ran.thrown()).isNull();
            assertThat(refusals).hasSize(2).allMatch(t -> t instanceof IllegalStateException);
            assertThat(capture.warnings()).as("the refusal C did not catch").hasSize(1);
            assertThat(fixture.entries("drain")).containsExactly("drain:D", "drain:C", "drain:B", "drain:A");
            assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
        }
    }

    @Test
    @DisplayName("A drain of a failed start that calls stop or start on its composition does not deadlock; the start still fails with its own exception")
    void drainOfAFailedStartCallsBack() throws Exception {
        Fixture fixture = new Fixture();
        failReady(fixture, "A");
        AtomicBoolean stopReturned = new AtomicBoolean();
        fixture.cap("D").onDrain = () -> {
            fixture.composition.stop(Duration.ofSeconds(1));
            stopReturned.set(true);
        };
        fixture.cap("C").onDrain = () -> fixture.composition.start();

        Ran ran = onThread(false, () -> {
            fixture.composition.start();
            return null;
        });

        assertThat(stopReturned).isTrue();
        assertThat(ran.thrown()).isInstanceOf(IllegalStateException.class).hasMessage("ready A");
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
    }

    @Test
    @DisplayName("A second stop from another thread waits for the first to finish and then does nothing")
    void concurrentSecondStopWaits() throws Exception {
        Fixture fixture = new Fixture();
        fixture.composition.start();
        java.util.concurrent.CountDownLatch inDrain = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        fixture.cap("C").onDrain = () -> {
            inDrain.countDown();
            release.await();
        };
        Thread[] second = new Thread[1];
        AtomicBoolean secondReturned = new AtomicBoolean();
        Thread first = new Thread(() -> fixture.composition.stop(Duration.ofSeconds(30)), "first-stop");
        first.setDaemon(true);
        first.start();
        assertThat(inDrain.await(BOUND_SECONDS, TimeUnit.SECONDS)).isTrue();
        second[0] = new Thread(() -> {
            fixture.composition.stop(Duration.ofSeconds(30));
            secondReturned.set(true);
        }, "second-stop");
        second[0].setDaemon(true);
        second[0].start();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (second[0].getState() != Thread.State.BLOCKED && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }

        assertThat(second[0].getState()).as("waiting for the monitor").isEqualTo(Thread.State.BLOCKED);
        assertThat(secondReturned).isFalse();
        assertThat(fixture.entries("terminate")).isEmpty();

        release.countDown();
        first.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
        second[0].join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));

        assertThat(first.isAlive() || second[0].isAlive()).isFalse();
        assertThat(secondReturned).isTrue();
        assertThat(fixture.entries("drain")).containsExactly("drain:D", "drain:C", "drain:B", "drain:A");
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
    }

    // ---- 7: a drain that ignores the interrupt -----------------------------------------------------------------

    @Test
    @DisplayName("A drain that ignores the interrupt holds the stop until it returns, and the stop then completes: no terminate runs while the drain runs, the later drains are skipped and every terminate follows")
    void drainThatIgnoresTheInterruptHoldsTheStop() throws Exception {
        Fixture fixture = new Fixture();
        AtomicBoolean release = new AtomicBoolean();
        AtomicBoolean sawInterrupt = new AtomicBoolean();
        fixture.cap("C").onDrain = () -> {
            while (!release.get()) {
                if (Thread.currentThread().isInterrupted()) {
                    sawInterrupt.set(true);
                }
                Thread.onSpinWait();
            }
        };
        fixture.composition.start();
        Object[] box = new Object[2];
        Thread stopping = new Thread(() -> {
            fixture.composition.stop(Duration.ofMillis(500));
            box[0] = Thread.currentThread().isInterrupted();
            box[1] = System.nanoTime();
        }, "stop-under-test");
        stopping.setDaemon(true);
        stopping.start();
        try {
            Thread.sleep(2_000);

            assertThat(stopping.isAlive()).as("held by the drain well after the budget").isTrue();
            assertThat(sawInterrupt).as("the watchdog interrupted it").isTrue();
            assertThat(fixture.entries("terminate")).as("never terminated while it drains").isEmpty();

            long released = System.nanoTime();
            release.set(true);
            stopping.join(5_000);

            assertThat(stopping.isAlive()).isFalse();
            assertThat(TimeUnit.NANOSECONDS.toMillis((Long) box[1] - released)).isLessThan(2_000);
            assertThat(box[0]).as("the flag after: the interrupt the drain ignored is kept for the caller").isEqualTo(true);
            fixture.caps.forEach(cap -> assertThat(cap.flagSeenByTerminate).as(cap.name).containsExactly(false));
            assertThat(fixture.entries("drain")).containsExactly("drain:D", "drain:C");
            assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
        } finally {
            release.set(true);
            stopping.interrupt();
        }
    }

    @Test
    @DisplayName("The Javadoc of stop says that a drain that ignores the interrupt keeps the stop until it returns")
    void javadocStatesThatAnIgnoredInterruptHoldsTheStop() throws IOException {
        String source = Files.readString(Path.of("src", "main", "java", "eu", "exeris", "sku", "identity",
                "IdentityComposition.java")).replaceAll("\\s*\\n\\s*\\*\\s*", " ");

        assertThat(source).contains("a drain that ignores the interrupt keeps the stop until it returns");
        assertThat(source).contains("never running when its capability's {@code terminate} is called");
    }

    /**
     * The caller's interrupt flag survives a drain that consumed it, a negative timeout of any size is an
     * exhausted budget, and the launcher reference states that a drain which ignores the interrupt holds
     * the stop and the process with it.
     */
    @org.junit.jupiter.api.Nested
    @DisplayName("Flag, timeout bounds and the reference text")
    class FlagAndBounds {

        @Test
        @DisplayName("The flag a caller entered with is still set after a drain consumed it by throwing InterruptedException, and the next drain sees it too")
        void flagConsumedByADrainIsRestored() throws Exception {
            Fixture fixture = new Fixture();
            fixture.cap("D").onDrain = () -> Thread.sleep(Duration.ofSeconds(30));

            Ran ran = stopped(fixture, Duration.ofSeconds(5), true);

            assertThat(ran.thrown()).isNull();
            assertThat(ran.flagAfter()).as("the caller's own flag").isTrue();
            assertThat(fixture.cap("C").flagSeenByDrain).as("the next drain").containsExactly(true);
        }

        @Test
        @DisplayName("A timeout below minus 292 years is a timeout that has run out, not 73 years")
        void hugelyNegativeTimeoutDrainsNothing() throws Exception {
            Fixture fixture = new Fixture();

            Ran ran = stopped(fixture, Duration.ofSeconds(Long.MIN_VALUE), false);

            assertThat(ran.thrown()).isNull();
            assertThat(fixture.entries("drain")).isEmpty();
            assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
        }

        @Test
        @DisplayName("The launcher reference says that a capability whose drain ignores the interrupt holds the stop")
        void referenceStatesThatAnIgnoredInterruptHoldsTheStop() throws IOException {
            String reference = Files.readString(Path.of("docs", "reference", "launcher.md"));

            assertThat(reference).containsPattern("(?i)ignores the interrupt");
        }
    }

    // ---- 8: errors and wrapped interrupts ----------------------------------------------------------------------

    private static final class Boom extends Error {
        private static final long serialVersionUID = 1L;

        Boom(String message) {
            super(message);
        }
    }

    @Test
    @DisplayName("An Error thrown by a drain after the watchdog fired: the unwind finishes, every terminate runs, the Error is rethrown after the last, the flag is clear")
    void errorAfterTheWatchdogFired() throws Exception {
        Fixture fixture = new Fixture();
        fixture.cap("C").onDrain = () -> {
            try {
                Thread.sleep(Duration.ofSeconds(120));
            } catch (InterruptedException interrupted) {
                throw new Boom("after the interrupt");
            }
        };
        fixture.cap("A").onTerminate = () -> {
            throw new Boom("terminate A");
        };

        Ran ran = stopped(fixture, Duration.ofMillis(500), false);

        assertThat(ran.thrown()).isInstanceOf(Boom.class).hasMessage("after the interrupt");
        assertThat(ran.thrown().getSuppressed()).hasSize(1);
        assertThat(ran.thrown().getSuppressed()[0]).hasMessage("terminate A");
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
        assertThat(ran.flagAfter()).isFalse();
    }

    @Test
    @DisplayName("A VirtualMachineError from a terminate takes the place of a drain's Error and carries it as suppressed")
    void virtualMachineErrorTakesPrecedence() throws Exception {
        Fixture fixture = new Fixture();
        fixture.cap("D").onDrain = () -> {
            throw new Boom("drain D");
        };
        fixture.cap("B").onTerminate = () -> {
            throw new OutOfMemoryError("terminate B");
        };

        Ran ran = stopped(fixture, Duration.ofSeconds(5), false);

        assertThat(ran.thrown()).isInstanceOf(OutOfMemoryError.class);
        assertThat(ran.thrown().getSuppressed()).hasSize(1);
        assertThat(ran.thrown().getSuppressed()[0]).hasMessage("drain D");
        assertThat(fixture.entries("drain")).containsExactly("drain:D", "drain:C", "drain:B", "drain:A");
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
    }

    @Test
    @DisplayName("A drain that wraps the watchdog's interrupt in its own exception: the exception is logged, the unwind goes on, and the caller's flag is clear")
    void wrappedInterruptAfterTheWatchdogFired() throws Exception {
        Fixture fixture = new Fixture();
        fixture.cap("C").onDrain = () -> {
            try {
                Thread.sleep(Duration.ofSeconds(120));
            } catch (InterruptedException interrupted) {
                throw new IllegalStateException(MESSAGE_MARKER, interrupted);
            }
        };

        Ran ran = stopped(fixture, Duration.ofMillis(500), false);

        assertThat(ran.thrown()).isNull();
        assertThat(fixture.entries("drain")).containsExactly("drain:D", "drain:C");
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
        assertThat(ran.flagAfter()).isFalse();
        fixture.caps.forEach(cap -> assertThat(cap.flagSeenByTerminate).as(cap.name).containsExactly(false));
    }

    @Test
    @DisplayName("A drain that throws InterruptedException of its own accord, with no watchdog involved, is logged as a failed drain and does not stop the unwind")
    void interruptedExceptionOfItsOwn() throws Exception {
        Fixture fixture = new Fixture();
        fixture.cap("D").onDrain = () -> {
            throw new InterruptedException(MESSAGE_MARKER);
        };
        try (Capture capture = new Capture()) {
            Ran ran = stopped(fixture, Duration.ofSeconds(5), false);

            assertThat(ran.thrown()).isNull();
            assertThat(fixture.entries("drain")).containsExactly("drain:D", "drain:C", "drain:B", "drain:A");
            assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
            assertThat(capture.warnings()).hasSize(1);
            assertThat(ran.flagAfter()).isFalse();
        }
    }

    @Test
    @DisplayName("The cleanup Error of a failed start is attached to the start's own exception, and a VirtualMachineError replaces it")
    void failedStartPrecedence() throws Exception {
        Fixture plain = new Fixture();
        failReady(plain, "B");
        plain.cap("C").onDrain = () -> {
            throw new Boom("drain C");
        };

        Ran ran = onThread(false, () -> {
            plain.composition.start();
            return null;
        });

        assertThat(ran.thrown()).isInstanceOf(IllegalStateException.class).hasMessage("ready B");
        assertThat(ran.thrown().getSuppressed()).hasSize(1);
        assertThat(ran.thrown().getSuppressed()[0]).hasMessage("drain C");

        Fixture fatal = new Fixture();
        failReady(fatal, "B");
        fatal.cap("C").onDrain = () -> {
            throw new OutOfMemoryError("drain C");
        };

        Ran fatalRan = onThread(false, () -> {
            fatal.composition.start();
            return null;
        });

        assertThat(fatalRan.thrown()).isInstanceOf(OutOfMemoryError.class);
        assertThat(fatalRan.thrown().getSuppressed()).hasSize(1);
        assertThat(fatalRan.thrown().getSuppressed()[0]).hasMessage("ready B");
        assertThat(fatal.entries("terminate")).containsExactlyElementsOf(TERMINATES);
    }
}
