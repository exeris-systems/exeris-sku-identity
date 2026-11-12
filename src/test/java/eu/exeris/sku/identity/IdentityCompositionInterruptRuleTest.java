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
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The rule for the calling thread's interrupt flag across a stop and across the unwind of a failed start,
 * stated as two invariants and checked over a table of interleavings.
 *
 * <ul>
 * <li>An interrupt the watchdog delivered is never visible to a later drain or to any terminate of the same
 *     stop: when a drain's watchdog fired, the flag is read and cleared at the end of that drain and stays
 *     clear until the stop returns.
 * <li>A stop request is never lost: the flag is set when the stop returns, normally or by throwing, if and
 *     only if it was set on entry or, for a drain whose watchdog fired, it was set when the watchdog fired
 *     or at the end of that drain.
 * </ul>
 *
 * When no watchdog fires the flag is not touched by the composition: each drain and terminate sees the flag
 * the one before it left, so a drain that consumes an interrupt, the entry flag included, leaves it consumed
 * for those that follow; the flag set on entry is still set on return. Every interleaving is
 * forced with latches; the capabilities are recording doubles, with no database and no kernel.
 */
@DisplayName("IdentityComposition: the rule for the interrupt flag across a stop")
class IdentityCompositionInterruptRuleTest {

    private static final String WATCHDOG = "identity-drain-watchdog";
    private static final long BOUND_SECONDS = 60;
    private static final Duration SHORT = Duration.ofMillis(250);
    private static final Duration GENEROUS = Duration.ofSeconds(60);
    private static final List<String> TERMINATES = List.of("terminate:D", "terminate:C", "terminate:B", "terminate:A");
    private static final List<String> DRAINS = List.of("drain:D", "drain:C", "drain:B", "drain:A");

    private static IdentityComposition base;
    private static Constructor<IdentityComposition> constructor;
    private static ServiceBoundaryCoreModule boundary;
    private static Method drainWithin;
    private static Constructor<?> debtConstructor;
    private static Method debtSettle;
    private static final List<String> NAMED_GAPS = new CopyOnWriteArrayList<>();

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
        Class<?> debt = Class.forName(IdentityComposition.class.getName() + "$InterruptDebt");
        drainWithin = IdentityComposition.class.getDeclaredMethod("drainWithin", CapabilityLifecycleHooks.class,
                Duration.class, debt);
        drainWithin.setAccessible(true);
        debtConstructor = debt.getDeclaredConstructor(boolean.class);
        debtConstructor.setAccessible(true);
        debtSettle = debt.getDeclaredMethod("settle");
        debtSettle.setAccessible(true);
    }

    /**
     * The rows in which a request existed and the flag is clear on return are the ones the rule cannot
     * honour: the drain's own call consumed the interrupt before the drain ended, after the fire or, when no
     * watchdog fires, by the rule that a drain leaves a consumed interrupt consumed. None has the flag set on
     * entry, and every drain in them consumes.
     */
    @AfterAll
    static void reportTheGaps() {
        System.out.println("RULE-TABLE rows the rule does not honour: " + NAMED_GAPS.size());
        NAMED_GAPS.stream().sorted().forEach(gap -> System.out.println("RULE-TABLE   " + gap));
        assertThat(NAMED_GAPS).allSatisfy(gap -> {
            assertThat(gap).contains("entry=clear");
            assertThat(gap).containsAnyOf("ending=RETURNS", "ending=THROWS_IE");
        });
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

    private static final class Cap implements CapabilityLifecycleHooks {
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

    /** What a third party does: sets the flag of {@code victim} from another thread, and is done when it returns. */
    private static void interruptFromAnotherThread(Thread victim) throws InterruptedException {
        Thread thirdParty = new Thread(victim::interrupt, "third-party");
        thirdParty.setDaemon(true);
        thirdParty.start();
        thirdParty.join();
    }

    // ---- forcing an interleaving ---------------------------------------------------------------------------

    private static final class Probe {
        final CountDownLatch started = new CountDownLatch(1);
        final CountDownLatch observed = new CountDownLatch(1);
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

        void requireBeforeTheDeadline() {
            long elapsed = System.nanoTime() - beganNanos;
            if (elapsed > slice.toNanos() / 2 || !watchdog.isAlive()) {
                throw new AssertionError("inconclusive: the third party interrupt was not clearly before the fire");
            }
        }

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

    private static void spinUntil(CountDownLatch latch) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
        while (latch.getCount() > 0) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("a latch was not counted down");
            }
            Thread.onSpinWait();
        }
    }

    private static void spinUntilEnded(Thread thread) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
        while (thread.isAlive()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("the watchdog did not fire");
            }
            Thread.onSpinWait();
        }
    }

    /** Sleeps until interrupted, which consumes the interrupt; returns when it has. */
    private static void sleepUntilInterrupted(Probe probe) {
        try {
            Thread.sleep(Duration.ofSeconds(120));
            throw new AssertionError("no interrupt arrived");
        } catch (InterruptedException interrupted) {
            probe.observed.countDown();
        }
    }

    private static void awaitNoWatchdog() {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (liveWatchdogs() > 0 && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        assertThat(liveWatchdogs()).as("watchdog threads alive").isZero();
    }

    private static long liveWatchdogs() {
        return Thread.getAllStackTraces().keySet().stream()
                .filter(t -> t.getName().equals(WATCHDOG) && t.isAlive()).count();
    }

    private static boolean noneTrue(List<Boolean> flags) {
        return flags.stream().noneMatch(b -> b);
    }

    private static Object newDebt(boolean owed) throws Exception {
        return debtConstructor.newInstance(owed);
    }

    private static void settle(Object debt) throws Exception {
        debtSettle.invoke(debt);
    }

    private static boolean drainWithin(Cap cap, Duration slice, Object debt) throws Exception {
        try {
            return (boolean) drainWithin.invoke(null, cap, slice, debt);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof Exception ex) {
                throw ex;
            }
            throw (Error) e.getCause();
        }
    }

    // ---- 1: the table --------------------------------------------------------------------------------------

    /** Who else interrupts the caller, and when, relative to the watchdog's fire. */
    private enum Third {
        /** Nobody; the watchdog's interrupt is pending at the end of the drain unless the drain consumes it. */
        NONE,
        /** Nobody; the drain consumes the watchdog's interrupt by blocking. */
        NONE_CONSUMED,
        /** A third party interrupts before the fire; the flag is already set when the watchdog fires. */
        BEFORE,
        /** A third party interrupts after the fire, while the watchdog's interrupt is still pending. */
        AFTER_PENDING,
        /** A third party interrupts after the fire, once the drain has consumed the watchdog's interrupt. */
        AFTER_CONSUMED
    }

    /** How the drain ends. */
    private enum Ending {
        /** Consumes whatever interrupt is pending and returns. */
        RETURNS,
        /** Consumes whatever interrupt is pending and throws InterruptedException. */
        THROWS_IE,
        /** Throws another exception without touching the flag. */
        THROWS_OTHER,
        /** Returns without touching the flag. */
        IGNORES,
        /** Restores the interrupt it caught, if it caught one, and throws a wrapping exception. */
        RESTORES_AND_WRAPS
    }

    private record Row(boolean entry, boolean fires, Third third, Ending ending) {

        @Override
        public String toString() {
            return "entry=" + (entry ? "set" : "clear") + " watchdog=" + (fires ? "fires" : "silent")
                    + " third=" + third + " ending=" + ending;
        }

        /** The watchdog's interrupt is pending, not consumed by a blocking call, when the drain reaches its end. */
        boolean watchdogPending() {
            return fires && (third == Third.NONE || third == Third.BEFORE || third == Third.AFTER_PENDING);
        }

        boolean requestExists() {
            return entry || third == Third.BEFORE || third == Third.AFTER_PENDING || third == Third.AFTER_CONSUMED;
        }
    }

    static Stream<Arguments> rows() {
        List<Arguments> rows = new ArrayList<>();
        for (boolean entry : new boolean[] {false, true}) {
            for (Ending ending : Ending.values()) {
                for (Third third : Third.values()) {
                    rows.add(Arguments.of(new Row(entry, true, third, ending)));
                }
                for (Third third : new Third[] {Third.NONE, Third.BEFORE}) {
                    rows.add(Arguments.of(new Row(entry, false, third, ending)));
                }
            }
        }
        return rows.stream();
    }

    private static void wire(Row row, Probe probe) {
        if (row.third() == Third.BEFORE) {
            probe.interruptWhen(probe.started);
        } else if (row.third() == Third.AFTER_PENDING || row.third() == Third.AFTER_CONSUMED) {
            probe.interruptWhen(probe.observed);
        }
    }

    /** The drain of a row; {@code flagAtEnd} receives the flag as the drain leaves it, whether it returns or throws. */
    private static Action script(Row row, Cap cap, Probe probe, AtomicReference<Boolean> flagAtEnd) {
        return () -> {
            probe.begin(cap);
            boolean caught = false;
            if (!row.fires()) {
                if (row.third() == Third.BEFORE) {
                    spinUntil(probe.sent);
                }
            } else {
                switch (row.third()) {
                    case NONE -> spinUntilEnded(probe.watchdog);
                    case BEFORE -> {
                        spinUntil(probe.sent);
                        probe.requireBeforeTheDeadline();
                        spinUntilEnded(probe.watchdog);
                    }
                    case AFTER_PENDING -> {
                        spinUntilEnded(probe.watchdog);
                        probe.observed.countDown();
                        spinUntil(probe.sent);
                    }
                    case NONE_CONSUMED -> {
                        Thread.interrupted();
                        sleepUntilInterrupted(probe);
                        caught = true;
                    }
                    case AFTER_CONSUMED -> {
                        Thread.interrupted();
                        sleepUntilInterrupted(probe);
                        caught = true;
                        spinUntil(probe.sent);
                    }
                }
            }
            switch (row.ending()) {
                case RETURNS -> {
                    Thread.interrupted();
                    flagAtEnd.set(Thread.currentThread().isInterrupted());
                }
                case IGNORES -> flagAtEnd.set(Thread.currentThread().isInterrupted());
                case THROWS_IE -> {
                    Thread.interrupted();
                    flagAtEnd.set(Thread.currentThread().isInterrupted());
                    throw new InterruptedException("thrown by the drain");
                }
                case THROWS_OTHER -> {
                    flagAtEnd.set(Thread.currentThread().isInterrupted());
                    throw new IllegalStateException("thrown by the drain");
                }
                case RESTORES_AND_WRAPS -> {
                    boolean had = Thread.interrupted() || caught;
                    if (had) {
                        Thread.currentThread().interrupt();
                    }
                    flagAtEnd.set(Thread.currentThread().isInterrupted());
                    throw new IllegalStateException("wrapped", new InterruptedException("caught by the drain"));
                }
            }
        };
    }

    /** What the rule says, computed from the facts of the row and the flag the drain ended with. */
    private record Expected(boolean flagOnReturn, boolean visibleToLaterDrainsAndTerminates) {

        static Expected of(Row row, boolean flagAtEnd) {
            boolean setWhenTheWatchdogFired = row.third() == Third.BEFORE || (row.entry() && row.watchdogPending());
            boolean onReturn = row.entry() || (row.fires() ? setWhenTheWatchdogFired || flagAtEnd : flagAtEnd);
            boolean visible = !row.fires() && flagAtEnd;
            return new Expected(onReturn, visible);
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("rows")
    @DisplayName("1. For each row: what every later drain and every terminate saw, and the flag on return, are those the rule states")
    void theRuleHoldsForEveryRow(Row row) throws Exception {
        AtomicReference<Boolean> flagAtEnd = new AtomicReference<>();

        // through stop: the terminates, and the later drains when none was skipped
        Fixture fixture = new Fixture();
        Probe probe = new Probe();
        wire(row, probe);
        fixture.cap("D").onDrain = script(row, fixture.cap("D"), probe, flagAtEnd);
        Ran viaStop = stopped(fixture, row.fires() ? SHORT : GENEROUS, row.entry());
        Expected expected = Expected.of(row, flagAtEnd.get());

        assertThat(viaStop.thrown()).as(row + ": stop throws nothing").isNull();
        assertThat(viaStop.flagAfter()).as(row + ": flag on return").isEqualTo(expected.flagOnReturn());
        assertThat(fixture.entries("terminate")).as(row.toString()).containsExactlyElementsOf(TERMINATES);
        fixture.caps.forEach(cap -> assertThat(cap.flagSeenByTerminate).as(row + ": terminate " + cap.name)
                .containsExactly(expected.visibleToLaterDrainsAndTerminates()));
        if (row.fires()) {
            assertThat(fixture.entries("drain")).as(row + ": the budget is used up, the later drains are skipped")
                    .containsExactly("drain:D");
        } else {
            assertThat(fixture.entries("drain")).as(row.toString()).containsExactlyElementsOf(DRAINS);
            fixture.caps.stream().filter(cap -> !cap.name.equals("D")).forEach(cap ->
                    assertThat(cap.flagSeenByDrain).as(row + ": drain " + cap.name)
                            .containsExactly(expected.visibleToLaterDrainsAndTerminates()));
        }

        // through drainWithin with a shared debt: a later drain after an overrun that leaves budget
        awaitNoWatchdog();
        AtomicReference<Boolean> flagAtEndSequence = new AtomicReference<>();
        Probe sequenceProbe = new Probe();
        wire(row, sequenceProbe);
        List<String> unused = Collections.synchronizedList(new ArrayList<>());
        Cap first = new Cap("X", unused);
        Cap later = new Cap("Y", unused);
        first.onDrain = script(row, first, sequenceProbe, flagAtEndSequence);
        Ran viaSequence = onThread(row.entry(), () -> {
            Object debt = newDebt(Thread.currentThread().isInterrupted());
            try {
                try {
                    drainWithin(first, row.fires() ? SHORT : GENEROUS, debt);
                } catch (Exception thrownByTheDrain) {
                    // logged by the stop, which goes on
                }
                drainWithin(later, GENEROUS, debt);
            } finally {
                settle(debt);
            }
            return null;
        });
        Expected expectedSequence = Expected.of(row, flagAtEndSequence.get());

        assertThat(viaSequence.thrown()).as(row.toString()).isNull();
        assertThat(later.flagSeenByDrain).as(row + ": the later drain")
                .containsExactly(expectedSequence.visibleToLaterDrainsAndTerminates());
        assertThat(viaSequence.flagAfter()).as(row + ": flag after the sequence")
                .isEqualTo(expectedSequence.flagOnReturn());

        if (row.requestExists() && !expected.flagOnReturn()) {
            NAMED_GAPS.add(row + (row.fires()
                    ? " -> LOST: an interrupt arrived after the fire and the drain consumed it before it ended"
                    : " -> CONSUMED by the drain, which leaves it consumed when no watchdog fires"));
        }
        awaitNoWatchdog();
    }

    // ---- 2: exceptional exits ------------------------------------------------------------------------------

    /** How the stop or the unwind meets the flag. */
    private enum Entry {
        /** Set on entry, no watchdog fires. */
        SET,
        /** Clear on entry, the watchdog fires and the drain leaves its interrupt pending. */
        OVERRUN,
        /** Clear on entry, the watchdog does not fire. */
        CLEAR;

        boolean flagOnReturn() {
            return this != CLEAR;
        }
    }

    private static Action overrunsLeavingTheInterruptPending(Probe probe, Cap cap) {
        return () -> {
            probe.begin(cap);
            spinUntilEnded(probe.watchdog);
        };
    }

    private static Duration budgetOf(Entry entry) {
        return entry == Entry.OVERRUN ? SHORT : GENEROUS;
    }

    static Stream<Arguments> errorsAndEntries() {
        List<Arguments> arguments = new ArrayList<>();
        for (Entry entry : Entry.values()) {
            arguments.add(Arguments.of("Error", entry));
            arguments.add(Arguments.of("VirtualMachineError", entry));
        }
        return arguments.stream();
    }

    private static Error errorOf(String kind) {
        return kind.equals("Error") ? new AssertionError("raised by a terminate") : new InternalError("raised by a terminate");
    }

    @ParameterizedTest(name = "{0}, {1}")
    @MethodSource("errorsAndEntries")
    @DisplayName("2a. A stop that throws because a terminate threw an Error or a VirtualMachineError: the Error is the one thrown, every terminate ran, and the flag is set on return exactly where the rule owes it")
    void stopThrowingAfterATerminateError(String kind, Entry entry) throws Exception {
        Fixture fixture = new Fixture();
        Probe probe = new Probe();
        Error raised = errorOf(kind);
        fixture.cap("D").onDrain = entry == Entry.OVERRUN
                ? overrunsLeavingTheInterruptPending(probe, fixture.cap("D")) : () -> { };
        fixture.cap("C").onTerminate = () -> {
            throw raised;
        };

        Ran ran = stopped(fixture, budgetOf(entry), entry == Entry.SET);

        assertThat(ran.thrown()).isSameAs(raised);
        assertThat(raised.getSuppressed()).isEmpty();
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
        assertThat(ran.flagAfter()).as("flag on return, " + entry).isEqualTo(entry.flagOnReturn());
        if (entry == Entry.OVERRUN) {
            fixture.caps.forEach(cap -> assertThat(noneTrue(cap.flagSeenByTerminate)).as(cap.name).isTrue());
        }
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(Entry.class)
    @DisplayName("2b. A stop that throws because a drain threw an Error after the fire: the Error is the one thrown and the flag is set on return exactly where the rule owes it")
    void stopThrowingAfterADrainError(Entry entry) throws Exception {
        Fixture fixture = new Fixture();
        Probe probe = new Probe();
        Error raised = new AssertionError("raised by a drain");
        fixture.cap("D").onDrain = () -> {
            if (entry == Entry.OVERRUN) {
                probe.begin(fixture.cap("D"));
                spinUntilEnded(probe.watchdog);
            }
            throw raised;
        };

        Ran ran = stopped(fixture, budgetOf(entry), entry == Entry.SET);

        assertThat(ran.thrown()).isSameAs(raised);
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
        assertThat(ran.flagAfter()).as("flag on return, " + entry).isEqualTo(entry.flagOnReturn());
        fixture.caps.stream().filter(cap -> entry == Entry.OVERRUN)
                .forEach(cap -> assertThat(noneTrue(cap.flagSeenByTerminate)).as(cap.name).isTrue());
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(Entry.class)
    @DisplayName("2c. The unwind of a start that failed in initialize: the failure is the one thrown, unchanged and with nothing suppressed, and the flag is set on return exactly where the rule owes it")
    void unwindOfAFailureInInitialize(Entry entry) throws Exception {
        Fixture fixture = new Fixture();
        Probe probe = new Probe();
        IllegalStateException failure = new IllegalStateException("initialize C");
        fixture.cap("C").onInitialize = () -> {
            throw failure;
        };
        if (entry == Entry.OVERRUN) {
            fixture.cap("B").onDrain = overrunsLeavingTheInterruptPending(probe, fixture.cap("B"));
        }

        Ran ran = onThread(entry == Entry.SET, () -> {
            fixture.composition.start();
            return null;
        });

        assertThat(ran.thrown()).isSameAs(failure);
        assertThat(failure.getSuppressed()).isEmpty();
        assertThat(fixture.entries("terminate")).containsExactly("terminate:C", "terminate:B", "terminate:A");
        assertThat(ran.flagAfter()).as("flag on return, " + entry).isEqualTo(entry.flagOnReturn());
        if (entry == Entry.OVERRUN) {
            assertThat(fixture.entries("drain")).containsExactly("drain:B");
            fixture.caps.forEach(cap -> assertThat(noneTrue(cap.flagSeenByTerminate)).as(cap.name).isTrue());
        }
    }

    @ParameterizedTest(name = "{0}")
    @EnumSource(Entry.class)
    @DisplayName("2d. The unwind of a start that failed in ready: the failure is the one thrown, unchanged and with nothing suppressed, and the flag is set on return exactly where the rule owes it")
    void unwindOfAFailureInReady(Entry entry) throws Exception {
        Fixture fixture = new Fixture();
        Probe probe = new Probe();
        IllegalStateException failure = new IllegalStateException("ready B");
        fixture.cap("B").onReady = () -> {
            throw failure;
        };
        if (entry == Entry.OVERRUN) {
            fixture.cap("D").onDrain = overrunsLeavingTheInterruptPending(probe, fixture.cap("D"));
        }

        Ran ran = onThread(entry == Entry.SET, () -> {
            fixture.composition.start();
            return null;
        });

        assertThat(ran.thrown()).isSameAs(failure);
        assertThat(failure.getSuppressed()).isEmpty();
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
        assertThat(ran.flagAfter()).as("flag on return, " + entry).isEqualTo(entry.flagOnReturn());
        if (entry == Entry.OVERRUN) {
            assertThat(fixture.entries("drain")).containsExactly("drain:D");
            fixture.caps.forEach(cap -> assertThat(noneTrue(cap.flagSeenByTerminate)).as(cap.name).isTrue());
        }
    }

    @Test
    @DisplayName("2e. The unwind of a start that failed with an Error from a terminate and an overrunning drain: the Error carries the start failure as suppressed, and the flag is set on return")
    void unwindWithACleanupErrorAfterAnOverrun() throws Exception {
        Fixture fixture = new Fixture();
        Probe probe = new Probe();
        IllegalStateException failure = new IllegalStateException("initialize C");
        Error raised = new InternalError("raised by a terminate");
        fixture.cap("C").onInitialize = () -> {
            throw failure;
        };
        fixture.cap("B").onDrain = overrunsLeavingTheInterruptPending(probe, fixture.cap("B"));
        fixture.cap("A").onTerminate = () -> {
            throw raised;
        };

        Ran ran = onThread(false, () -> {
            fixture.composition.start();
            return null;
        });

        assertThat(ran.thrown()).isSameAs(raised);
        assertThat(raised.getSuppressed()).containsExactly(failure);
        assertThat(ran.flagAfter()).isTrue();
    }

    // ---- 3: a terminate that consumes the entry flag -------------------------------------------------------

    private static Fixture fixtureWhoseTerminateConsumes(String name, boolean blocking) {
        Fixture fixture = new Fixture();
        fixture.cap(name).onTerminate = blocking
                ? () -> {
                    try {
                        Thread.sleep(Duration.ofSeconds(30));
                    } catch (InterruptedException caught) {
                        // the terminate gives up waiting
                    }
                }
                : Thread::interrupted;
        return fixture;
    }

    @ParameterizedTest(name = "blocking={0}")
    @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
    @DisplayName("3a. A flag set on entry, no watchdog fires, and a terminate consumes it: the terminate saw it, and the flag is set on return because it was set on entry")
    void entryFlagConsumedByATerminateIsSetOnReturn(boolean blocking) throws Exception {
        Fixture fixture = fixtureWhoseTerminateConsumes("C", blocking);

        Ran ran = stopped(fixture, GENEROUS, true);

        assertThat(ran.thrown()).isNull();
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(TERMINATES);
        assertThat(fixture.cap("D").flagSeenByTerminate).containsExactly(true);
        assertThat(fixture.cap("C").flagSeenByTerminate).containsExactly(true);
        assertThat(ran.flagAfter()).as("set on entry, so set on return, although a terminate consumed it").isTrue();
    }

    @ParameterizedTest(name = "blocking={0}")
    @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
    @DisplayName("3b. A flag set on entry, no watchdog fires, and a terminate consumes it: the later terminates see it clear, and the flag is set on return")
    void entryFlagConsumedByATerminateIsClearForTheLaterTerminates(boolean blocking) throws Exception {
        Fixture fixture = fixtureWhoseTerminateConsumes("C", blocking);

        Ran ran = stopped(fixture, GENEROUS, true);

        assertThat(fixture.cap("B").flagSeenByTerminate).as("terminate B, after the consuming terminate C")
                .containsExactly(false);
        assertThat(fixture.cap("A").flagSeenByTerminate).as("terminate A").containsExactly(false);
        assertThat(ran.flagAfter()).as("set on entry, so set on return").isTrue();
    }

    @Test
    @DisplayName("3c. A flag set by a third party during a drain, no watchdog fires, and a terminate consumes it: it stays consumed, the flag is clear on return")
    void interruptConsumedByATerminateStaysConsumed() throws Exception {
        Fixture fixture = fixtureWhoseTerminateConsumes("C", false);
        fixture.cap("D").onDrain = () -> interruptFromAnotherThread(Thread.currentThread());

        Ran ran = stopped(fixture, GENEROUS, false);

        assertThat(ran.thrown()).isNull();
        assertThat(fixture.cap("D").flagSeenByTerminate).containsExactly(true);
        assertThat(fixture.cap("C").flagSeenByTerminate).containsExactly(true);
        assertThat(fixture.cap("B").flagSeenByTerminate).containsExactly(false);
        assertThat(ran.flagAfter()).isFalse();
    }

    // ---- 4: no watchdog fires, an interrupt that arrives between drains ----------------------------------------

    @Test
    @DisplayName("4. A third party interrupts during one drain and the next drain consumes it, no watchdog fires: it stays consumed for the later drains, the terminates and the caller")
    void aDrainThatConsumesAnInterruptOfAnEarlierDrainLeavesItConsumed() throws Exception {
        Fixture fixture = new Fixture();
        fixture.cap("D").onDrain = () -> interruptFromAnotherThread(Thread.currentThread());
        fixture.cap("C").onDrain = Thread::interrupted;

        Ran ran = stopped(fixture, GENEROUS, false);

        assertThat(ran.thrown()).isNull();
        assertThat(fixture.cap("C").flagSeenByDrain).as("C saw the interrupt").containsExactly(true);
        assertThat(fixture.cap("B").flagSeenByDrain).as("B, after C consumed it").containsExactly(false);
        assertThat(fixture.cap("A").flagSeenByDrain).containsExactly(false);
        fixture.caps.forEach(cap -> assertThat(cap.flagSeenByTerminate).as("terminate " + cap.name).containsExactly(false));
        assertThat(ran.flagAfter()).isFalse();
    }
}
