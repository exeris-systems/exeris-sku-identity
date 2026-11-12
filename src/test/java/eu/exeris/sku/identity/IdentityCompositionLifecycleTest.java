package eu.exeris.sku.identity;

import eu.exeris.caps.serviceboundarycore.ServiceBoundaryCoreModule;
import eu.exeris.kernel.community.security.Argon2idPasswordEncoder;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.security.credentials.PasswordEncoderConfig;
import eu.exeris.sdk.composition.lifecycle.CapabilityLifecycleHooks;
import eu.exeris.sku.identity.config.IdentityConfig;
import eu.exeris.sku.identity.http.IdentityRoutes;
import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.JdbcTransactionalExecutor;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.RecordingNotificationDispatcher;
import eu.exeris.sku.identity.support.TestConfig;
import eu.exeris.sku.identity.support.TestExchange;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The lifecycle of {@link IdentityComposition} over recording capability doubles, with no database and no
 * kernel. The composition is assembled through its private constructor so that its ready order is made of
 * doubles that record every call and can block or fail on demand; the wiring around it is the real builder's.
 */
@DisplayName("IdentityComposition lifecycle")
class IdentityCompositionLifecycleTest {

    private static final Duration DRAIN = Duration.ofSeconds(1);
    private static final long BOUND_SECONDS = 20;
    private static final int ROUNDS = 2_000;

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

    /** A capability that records each call at its entry, and can be made to wait or to fail. */
    private static final class Hook implements CapabilityLifecycleHooks {
        final String name;
        final List<String> log;
        volatile Action onInitialize = () -> { };
        volatile Action onReady = () -> { };
        volatile Action onDrain = () -> { };
        volatile Action onTerminate = () -> { };
        final List<Duration> drainBudgets = new java.util.concurrent.CopyOnWriteArrayList<>();

        Hook(String name, List<String> log) {
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
            drainBudgets.add(timeout);
            onDrain.run();
        }

        @Override
        public void terminate() {
            log.add("terminate:" + name);
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
        final List<Hook> hooks = List.of(new Hook("A", log), new Hook("B", log), new Hook("C", log), new Hook("D", log));
        final IdentityComposition composition;

        Fixture() {
            try {
                composition = constructor.newInstance(boundary, new ArrayList<CapabilityLifecycleHooks>(hooks),
                        base.jwtAdmissionPolicy(), base.jwtBinding(), base.services());
            } catch (ReflectiveOperationException e) {
                throw new AssertionError(e);
            }
        }

        Hook hook(String name) {
            return hooks.stream().filter(h -> h.name.equals(name)).findFirst().orElseThrow();
        }

        List<String> entries(String kind) {
            synchronized (log) {
                return log.stream().filter(e -> e.startsWith(kind + ":")).toList();
            }
        }

        List<String> snapshot() {
            synchronized (log) {
                return List.copyOf(log);
            }
        }
    }

    private static final List<String> FULL_RUN = List.of(
            "initialize:A", "initialize:B", "initialize:C", "initialize:D",
            "ready:A", "ready:B", "ready:C", "ready:D",
            "drain:D", "drain:C", "drain:B", "drain:A",
            "terminate:D", "terminate:C", "terminate:B", "terminate:A");

    private static void awaitCondition(String what, java.util.function.BooleanSupplier condition) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(BOUND_SECONDS);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("never observed: " + what);
            }
            Thread.onSpinWait();
        }
    }

    private static <T> T within(Future<T> future) throws Exception {
        try {
            return future.get(BOUND_SECONDS, TimeUnit.SECONDS);
        } catch (TimeoutException hung) {
            throw new AssertionError("a call did not return within " + BOUND_SECONDS + " s", hung);
        }
    }

    // ---- 11 --------------------------------------------------------------------------------------------

    @Test
    @DisplayName("stop then start is refused; stop then tryStart returns false; nothing is ever initialised")
    void stopBeforeStart() throws Exception {
        Fixture started = new Fixture();
        started.composition.stop(DRAIN);

        assertThatThrownBy(started.composition::start).isInstanceOf(IllegalStateException.class);
        assertThat(started.snapshot()).isEmpty();

        Fixture tried = new Fixture();
        tried.composition.stop(DRAIN);

        assertThat(tried.composition.tryStart()).isFalse();
        assertThat(tried.composition.tryStart()).isFalse();
        assertThat(tried.snapshot()).as("no capability was initialised, drained or terminated").isEmpty();
    }

    // ---- 12 --------------------------------------------------------------------------------------------

    @Test
    @DisplayName("tryStart on a fresh composition starts it; a second tryStart or start throws; stop terminates everything; a second stop is harmless")
    void tryStartOnAFreshComposition() throws Exception {
        Fixture fixture = new Fixture();

        assertThat(fixture.composition.tryStart()).isTrue();
        assertThatThrownBy(fixture.composition::tryStart).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(fixture.composition::start).isInstanceOf(IllegalStateException.class);
        assertThat(fixture.snapshot()).containsExactly("initialize:A", "initialize:B", "initialize:C", "initialize:D",
                "ready:A", "ready:B", "ready:C", "ready:D");

        fixture.composition.stop(DRAIN);
        assertThat(fixture.snapshot()).containsExactlyElementsOf(FULL_RUN);

        fixture.composition.stop(DRAIN);
        assertThat(fixture.snapshot()).as("a second stop does nothing").containsExactlyElementsOf(FULL_RUN);
        assertThatThrownBy(fixture.composition::start).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(fixture.composition::tryStart).isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("start on a fresh composition runs the same order as tryStart")
    void startRunsTheSameOrder() throws Exception {
        Fixture fixture = new Fixture();

        fixture.composition.start();
        fixture.composition.stop(DRAIN);

        assertThat(fixture.snapshot()).containsExactlyElementsOf(FULL_RUN);
    }

    // ---- 13 --------------------------------------------------------------------------------------------

    private void stopDuringStartWaitsForTheStart(String blockedHook, boolean inInitialize) throws Exception {
        Fixture fixture = new Fixture();
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Action block = () -> {
            entered.countDown();
            release.await();
        };
        if (inInitialize) {
            fixture.hook(blockedHook).onInitialize = block;
        } else {
            fixture.hook(blockedHook).onReady = block;
        }
        ExecutorService pool = Executors.newFixedThreadPool(2);
        AtomicBoolean stopReturned = new AtomicBoolean();
        try {
            Future<Boolean> starting = pool.submit(fixture.composition::tryStart);
            assertThat(entered.await(BOUND_SECONDS, TimeUnit.SECONDS)).isTrue();
            Thread[] stopper = new Thread[1];
            Future<?> stopping = pool.submit(() -> {
                stopper[0] = Thread.currentThread();
                fixture.composition.stop(DRAIN);
                stopReturned.set(true);
            });
            awaitCondition("the stop is queued on the composition's monitor",
                    () -> stopper[0] != null && stopper[0].getState() == Thread.State.BLOCKED);

            assertThat(stopReturned.get()).as("stop returned while the start was still running").isFalse();
            assertThat(fixture.entries("drain")).isEmpty();
            assertThat(fixture.entries("terminate")).isEmpty();

            release.countDown();
            assertThat(within(starting)).isTrue();
            within(stopping);

            assertThat(fixture.snapshot()).containsExactlyElementsOf(FULL_RUN);
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("A stop issued while another thread is inside start waits for it, then drains and terminates what started, in order")
    void stopDuringStart() throws Exception {
        stopDuringStartWaitsForTheStart("A", true);
        stopDuringStartWaitsForTheStart("C", true);
        stopDuringStartWaitsForTheStart("D", true);
        stopDuringStartWaitsForTheStart("A", false);
        stopDuringStartWaitsForTheStart("C", false);
        stopDuringStartWaitsForTheStart("D", false);
    }

    // ---- 14 --------------------------------------------------------------------------------------------

    @Test
    @DisplayName("A start whose ready throws drains every capability, then terminates every one, ends stopped, refuses start and tryStart, and a stop does nothing")
    void failedStartInReady() {
        Fixture fixture = new Fixture();
        IllegalStateException failure = new IllegalStateException("ready C");
        fixture.hook("C").onReady = () -> {
            throw failure;
        };

        assertThatThrownBy(fixture.composition::start).isSameAs(failure);

        List<String> expected = List.of("initialize:A", "initialize:B", "initialize:C", "initialize:D",
                "ready:A", "ready:B", "ready:C", "drain:D", "drain:C", "drain:B", "drain:A",
                "terminate:D", "terminate:C", "terminate:B", "terminate:A");
        assertThat(fixture.snapshot()).containsExactlyElementsOf(expected);
        assertThatThrownBy(fixture.composition::start).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(fixture.composition::tryStart).isInstanceOf(IllegalStateException.class);
        fixture.composition.stop(DRAIN);
        assertThat(fixture.snapshot()).as("stop after a failed start does nothing").containsExactlyElementsOf(expected);
    }

    @Test
    @DisplayName("tryStart on a composition whose start failed throws instead of returning false (no stop came first)")
    void tryStartAfterAFailedStart() {
        Fixture fixture = new Fixture();
        fixture.hook("B").onReady = () -> {
            throw new IllegalStateException("ready B");
        };
        assertThatThrownBy(fixture.composition::tryStart).isInstanceOf(IllegalStateException.class);

        assertThatThrownBy(fixture.composition::tryStart).isInstanceOf(IllegalStateException.class)
                .hasMessageNotContaining("has been stopped");
    }

    @Test
    @DisplayName("A start whose initialize throws drains the ones that completed it, then terminates the one that threw and those before it, in reverse order, and touches none after it")
    void failedStartInInitialize() {
        Fixture fixture = new Fixture();
        fixture.hook("C").onInitialize = () -> {
            throw new IllegalStateException("initialize C");
        };

        assertThatThrownBy(fixture.composition::start).isInstanceOf(IllegalStateException.class);

        assertThat(fixture.snapshot()).containsExactly("initialize:A", "initialize:B", "initialize:C",
                "drain:B", "drain:A", "terminate:C", "terminate:B", "terminate:A");
    }

    @Test
    @DisplayName("A start that fails with an Error terminates what was initialised, ends stopped and rethrows the Error")
    void failedStartWithAnError() {
        Fixture fixture = new Fixture();
        NoClassDefFoundError failure = new NoClassDefFoundError("ready B");
        fixture.hook("B").onReady = () -> {
            throw failure;
        };

        assertThatThrownBy(fixture.composition::start).isSameAs(failure);

        assertThat(fixture.entries("terminate")).containsExactly("terminate:D", "terminate:C", "terminate:B", "terminate:A");
        assertThatThrownBy(fixture.composition::start).isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("A terminate that throws during a failed start does not stop the others from being terminated")
    void terminateFailureDuringAFailedStart() {
        Fixture fixture = new Fixture();
        fixture.hook("B").onReady = () -> {
            throw new IllegalStateException("ready B");
        };
        fixture.hook("C").onTerminate = () -> {
            throw new IllegalStateException("terminate C");
        };

        assertThatThrownBy(fixture.composition::start).hasMessage("ready B");

        assertThat(fixture.entries("terminate")).containsExactly("terminate:D", "terminate:C", "terminate:B", "terminate:A");
    }

    @Test
    @DisplayName("During a stop a drain that throws, or a terminate that throws, does not stop the others from being drained and terminated")
    void drainAndTerminateFailuresDuringAStop() throws Exception {
        Fixture fixture = new Fixture();
        fixture.hook("C").onDrain = () -> {
            throw new IllegalStateException("drain C");
        };
        fixture.hook("B").onTerminate = () -> {
            throw new IllegalStateException("terminate B");
        };
        fixture.composition.start();

        fixture.composition.stop(DRAIN);

        assertThat(fixture.entries("drain")).containsExactly("drain:D", "drain:C", "drain:B", "drain:A");
        assertThat(fixture.entries("terminate")).containsExactly("terminate:D", "terminate:C", "terminate:B", "terminate:A");
    }

    @Test
    @DisplayName("During a stop a terminate that throws an Error does not leave the remaining capabilities unterminated")
    void terminateErrorDuringAStop() throws Exception {
        Fixture fixture = new Fixture();
        fixture.hook("C").onTerminate = () -> {
            throw new NoClassDefFoundError("terminate C");
        };
        fixture.composition.start();

        try {
            fixture.composition.stop(DRAIN);
        } catch (Error expectedToPropagate) {
            // whether the Error propagates is not what is under test
        }

        assertThat(fixture.entries("terminate")).containsExactly("terminate:D", "terminate:C", "terminate:B", "terminate:A");
        assertThatThrownBy(fixture.composition::start).isInstanceOf(IllegalStateException.class);
    }

    // ---- 15 --------------------------------------------------------------------------------------------

    @Test
    @DisplayName("Racing stop against tryStart: a started composition is fully terminated when stop returns; a refused one never initialised anything")
    void stopRacingTryStart() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        int started = 0;
        int refused = 0;
        try {
            for (int round = 0; round < ROUNDS; round++) {
                Fixture fixture = new Fixture();
                CyclicBarrier barrier = new CyclicBarrier(2);
                Future<Boolean> starting = pool.submit(() -> {
                    barrier.await(BOUND_SECONDS, TimeUnit.SECONDS);
                    return fixture.composition.tryStart();
                });
                Future<?> stopping = pool.submit(() -> {
                    barrier.await(BOUND_SECONDS, TimeUnit.SECONDS);
                    fixture.composition.stop(DRAIN);
                    return null;
                });

                boolean didStart = within(starting);
                within(stopping);

                if (didStart) {
                    started++;
                    assertThat(fixture.snapshot()).as("round %d", round).containsExactlyElementsOf(FULL_RUN);
                } else {
                    refused++;
                    assertThat(fixture.snapshot()).as("round %d: a refused start initialised something", round).isEmpty();
                }
            }
        } finally {
            pool.shutdownNow();
        }
        System.out.println("[stop-vs-tryStart] started=" + started + " refused=" + refused);
    }

    // ---- 16 --------------------------------------------------------------------------------------------

    @Test
    @DisplayName("Only start, tryStart and stop take the composition's monitor; no accessor the request path uses is synchronized")
    void onlyTheLifecycleTakesTheMonitor() {
        List<String> synchronizedMethods = new ArrayList<>();
        for (Method method : IdentityComposition.class.getDeclaredMethods()) {
            if (Modifier.isSynchronized(method.getModifiers())) {
                synchronizedMethods.add(method.getName());
            }
        }

        assertThat(synchronizedMethods).containsExactlyInAnyOrder("start", "tryStart", "stop");
    }

    @Test
    @DisplayName("While a stop holds the monitor in a slow drain, and while a start holds it in a slow initialise, a request is still answered")
    void requestsAreServedWhileTheMonitorIsHeld() throws Exception {
        for (boolean duringStop : new boolean[] {true, false}) {
            Fixture fixture = new Fixture();
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            Action block = () -> {
                entered.countDown();
                release.await();
            };
            ExecutorService pool = Executors.newFixedThreadPool(3);
            try {
                Future<?> holder;
                if (duringStop) {
                    fixture.hook("D").onDrain = block;
                    fixture.composition.start();
                    holder = pool.submit(() -> fixture.composition.stop(DRAIN));
                } else {
                    fixture.hook("B").onInitialize = block;
                    holder = pool.submit(() -> {
                        fixture.composition.start();
                        return null;
                    });
                }
                assertThat(entered.await(BOUND_SECONDS, TimeUnit.SECONDS)).isTrue();

                Future<Object> request = pool.submit(() -> {
                    TestExchange exchange = TestExchange.of(HttpMethod.GET, "/health-probe-unknown");
                    fixture.composition.httpHandler().handle(exchange);
                    fixture.composition.apiSurfaceRegistry();
                    fixture.composition.requestFilterChain();
                    fixture.composition.services();
                    fixture.composition.jwksPublisher();
                    return exchange.status();
                });

                assertThat(within(request)).as(duringStop ? "during a stop" : "during a start").isNotNull();
                assertThat(holder.isDone()).as("the monitor holder is still inside its call").isFalse();

                release.countDown();
                within(holder);
            } finally {
                release.countDown();
                pool.shutdownNow();
            }
        }
    }

    // ---- the unwind: Errors, precedence, messages ----------------------------------------------------------

    private static final List<String> ALL_DRAINS = List.of("drain:D", "drain:C", "drain:B", "drain:A");
    private static final List<String> ALL_TERMINATES = List.of("terminate:D", "terminate:C", "terminate:B", "terminate:A");

    @Test
    @DisplayName("A drain that throws an Error does not skip a later drain or any terminate; the Error is rethrown after the last terminate")
    void drainErrorIsRethrownAfterTheLastTerminate() throws Exception {
        Fixture fixture = new Fixture();
        NoClassDefFoundError failure = new NoClassDefFoundError("drain C");
        fixture.hook("C").onDrain = () -> {
            throw failure;
        };
        fixture.composition.start();

        assertThatThrownBy(() -> fixture.composition.stop(DRAIN)).isSameAs(failure);

        assertThat(fixture.entries("drain")).containsExactlyElementsOf(ALL_DRAINS);
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(ALL_TERMINATES);
        assertThat(fixture.snapshot().get(fixture.snapshot().size() - 1)).isEqualTo("terminate:A");
        assertThat(failure.getSuppressed()).isEmpty();
        fixture.composition.stop(DRAIN);
        assertThat(fixture.entries("terminate")).as("a second stop does nothing").hasSize(4);
    }

    @Test
    @DisplayName("Several Errors in one stop: the first is rethrown with the later ones suppressed, whichever phase threw them")
    void firstErrorKeptLaterSuppressed() throws Exception {
        Fixture fixture = new Fixture();
        NoClassDefFoundError first = new NoClassDefFoundError("drain D");
        LinkageError second = new LinkageError("drain B");
        ExceptionInInitializerError third = new ExceptionInInitializerError("terminate C");
        fixture.hook("D").onDrain = () -> {
            throw first;
        };
        fixture.hook("B").onDrain = () -> {
            throw second;
        };
        fixture.hook("C").onTerminate = () -> {
            throw third;
        };
        fixture.composition.start();

        assertThatThrownBy(() -> fixture.composition.stop(DRAIN)).isSameAs(first);

        assertThat(first.getSuppressed()).containsExactlyInAnyOrder(second, third);
        assertThat(fixture.entries("drain")).containsExactlyElementsOf(ALL_DRAINS);
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(ALL_TERMINATES);
    }

    @Test
    @DisplayName("A VirtualMachineError takes precedence over an earlier ordinary Error, which is suppressed onto it; an earlier one keeps its place against a later ordinary Error")
    void virtualMachineErrorTakesPrecedence() throws Exception {
        Fixture later = new Fixture();
        NoClassDefFoundError ordinary = new NoClassDefFoundError("drain C");
        OutOfMemoryError fatal = new OutOfMemoryError("terminate B");
        later.hook("C").onDrain = () -> {
            throw ordinary;
        };
        later.hook("B").onTerminate = () -> {
            throw fatal;
        };
        later.composition.start();

        assertThatThrownBy(() -> later.composition.stop(DRAIN)).isSameAs(fatal);

        assertThat(fatal.getSuppressed()).containsExactly(ordinary);
        assertThat(later.entries("terminate")).containsExactlyElementsOf(ALL_TERMINATES);

        Fixture earlier = new Fixture();
        OutOfMemoryError firstFatal = new OutOfMemoryError("drain C");
        NoClassDefFoundError laterOrdinary = new NoClassDefFoundError("terminate B");
        earlier.hook("C").onDrain = () -> {
            throw firstFatal;
        };
        earlier.hook("B").onTerminate = () -> {
            throw laterOrdinary;
        };
        earlier.composition.start();

        assertThatThrownBy(() -> earlier.composition.stop(DRAIN)).isSameAs(firstFatal);

        assertThat(firstFatal.getSuppressed()).containsExactly(laterOrdinary);
    }

    @Test
    @DisplayName("A failed start throws the original failure with an Error from a cleanup terminate suppressed onto it, and still terminates every capability")
    void cleanupErrorIsSuppressedOntoTheStartFailure() {
        Fixture fixture = new Fixture();
        IllegalStateException failure = new IllegalStateException("ready B");
        NoClassDefFoundError cleanup = new NoClassDefFoundError("terminate C");
        fixture.hook("B").onReady = () -> {
            throw failure;
        };
        fixture.hook("C").onTerminate = () -> {
            throw cleanup;
        };

        assertThatThrownBy(fixture.composition::start).isSameAs(failure);

        assertThat(failure.getSuppressed()).containsExactly(cleanup);
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(ALL_TERMINATES);
    }

    @Test
    @DisplayName("A failed start whose cleanup threw a VirtualMachineError throws that error, with the start failure suppressed onto it")
    void cleanupFatalErrorTakesPrecedenceOverTheStartFailure() {
        Fixture fixture = new Fixture();
        IllegalStateException failure = new IllegalStateException("ready B");
        OutOfMemoryError fatal = new OutOfMemoryError("terminate C");
        fixture.hook("B").onReady = () -> {
            throw failure;
        };
        fixture.hook("C").onTerminate = () -> {
            throw fatal;
        };

        assertThatThrownBy(fixture.composition::start).isSameAs(fatal);

        assertThat(fatal.getSuppressed()).containsExactly(failure);
        assertThat(fixture.entries("terminate")).containsExactlyElementsOf(ALL_TERMINATES);
    }

    @Test
    @DisplayName("A start that fails with an Error and a cleanup that throws another: the start's Error is thrown with the cleanup's suppressed")
    void errorStartFailureWithErrorCleanup() {
        Fixture fixture = new Fixture();
        NoClassDefFoundError failure = new NoClassDefFoundError("ready B");
        LinkageError cleanup = new LinkageError("terminate A");
        fixture.hook("B").onReady = () -> {
            throw failure;
        };
        fixture.hook("A").onTerminate = () -> {
            throw cleanup;
        };

        assertThatThrownBy(fixture.composition::start).isSameAs(failure);

        assertThat(failure.getSuppressed()).containsExactly(cleanup);
    }

    @Test
    @DisplayName("The messages say which of the three endings refused the start, and tryStart is false only for a stop that came first")
    void messagesAndTryStart() throws Exception {
        Fixture stoppedFirst = new Fixture();
        stoppedFirst.composition.stop(DRAIN);
        assertThatThrownBy(stoppedFirst.composition::start).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("has been stopped before it was started");
        assertThat(stoppedFirst.composition.tryStart()).isFalse();
        assertThat(stoppedFirst.composition.tryStart()).as("and again").isFalse();

        Fixture failed = new Fixture();
        failed.hook("B").onInitialize = () -> {
            throw new IllegalStateException("initialize B");
        };
        assertThatThrownBy(failed.composition::start).hasMessage("initialize B");
        for (Action again : List.<Action>of(failed.composition::start, failed.composition::tryStart)) {
            assertThatThrownBy(again::run).isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("start failed and it was stopped; a composition is started at most once")
                    .hasMessageNotContaining("before it was started");
        }

        Fixture stopped = new Fixture();
        stopped.composition.start();
        stopped.composition.stop(DRAIN);
        for (Action again : List.<Action>of(stopped.composition::start, stopped.composition::tryStart)) {
            assertThatThrownBy(again::run).isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("has been started and stopped")
                    .hasMessageNotContaining("before it was started");
        }

        Fixture running = new Fixture();
        assertThat(running.composition.tryStart()).isTrue();
        for (Action again : List.<Action>of(running.composition::start, running.composition::tryStart)) {
            assertThatThrownBy(again::run).isInstanceOf(IllegalStateException.class).hasMessageContaining("has been started")
                    .hasMessageNotContaining("stopped");
        }
        running.composition.stop(DRAIN);
    }

    private static final List<String> NAMES = List.of("A", "B", "C", "D");

    /** The calls of a start that fails at the {@code position}-th capability (0-based) of the given phase. */
    private static List<String> expectedUnwind(int position, boolean inInitialize) {
        List<String> expected = new ArrayList<>();
        int drained;
        if (inInitialize) {
            for (int i = 0; i <= position; i++) {
                expected.add("initialize:" + NAMES.get(i));
            }
            drained = position - 1;
        } else {
            NAMES.forEach(name -> expected.add("initialize:" + name));
            for (int i = 0; i <= position; i++) {
                expected.add("ready:" + NAMES.get(i));
            }
            drained = NAMES.size() - 1;
        }
        for (int i = drained; i >= 0; i--) {
            expected.add("drain:" + NAMES.get(i));
        }
        for (int i = inInitialize ? position : NAMES.size() - 1; i >= 0; i--) {
            expected.add("terminate:" + NAMES.get(i));
        }
        return expected;
    }

    @Test
    @DisplayName("A start that fails in initialize at each of four positions drains the completed prefix in reverse, never the one that threw, then terminates it and the prefix in reverse")
    void failedInitializeAtEveryPosition() {
        for (int position = 0; position < NAMES.size(); position++) {
            String failing = NAMES.get(position);
            Fixture fixture = new Fixture();
            fixture.hook(failing).onInitialize = () -> {
                throw new IllegalStateException("initialize " + failing);
            };

            assertThatThrownBy(fixture.composition::start).hasMessage("initialize " + failing);

            assertThat(fixture.snapshot()).as(failing).containsExactlyElementsOf(expectedUnwind(position, true));
            assertThat(fixture.entries("ready")).as(failing).isEmpty();
            assertThatThrownBy(fixture.composition::tryStart).as(failing).isInstanceOf(IllegalStateException.class);
            fixture.composition.stop(DRAIN);
            assertThat(fixture.snapshot()).as("%s: a stop after the failed start does nothing", failing)
                    .containsExactlyElementsOf(expectedUnwind(position, true));
        }
    }

    @Test
    @DisplayName("A start that fails in ready at each of four positions drains every capability, the one whose ready threw included, in reverse, then terminates every one in reverse")
    void failedReadyAtEveryPosition() {
        for (int position = 0; position < NAMES.size(); position++) {
            String failing = NAMES.get(position);
            Fixture fixture = new Fixture();
            fixture.hook(failing).onReady = () -> {
                throw new IllegalStateException("ready " + failing);
            };

            assertThatThrownBy(fixture.composition::start).hasMessage("ready " + failing);

            assertThat(fixture.snapshot()).as(failing).containsExactlyElementsOf(expectedUnwind(position, false));
            fixture.composition.stop(DRAIN);
            assertThat(fixture.snapshot()).as("%s: a stop after the failed start does nothing", failing)
                    .containsExactlyElementsOf(expectedUnwind(position, false));
        }
    }

    @Test
    @DisplayName("An Error thrown by a drain during the unwind of a failed start, at each position, stops neither the remaining drains nor any terminate, and is suppressed onto the start failure")
    void drainErrorDuringTheUnwindOfAFailedStart() {
        for (boolean inInitialize : List.of(true, false)) {
            for (int position = 0; position < NAMES.size(); position++) {
                for (String erring : NAMES) {
                    String failing = NAMES.get(position);
                    List<String> expected = expectedUnwind(position, inInitialize);
                    if (!expected.contains("drain:" + erring)) {
                        continue;
                    }
                    String what = (inInitialize ? "initialize " : "ready ") + failing + ", drain error in " + erring;
                    Fixture fixture = new Fixture();
                    IllegalStateException failure = new IllegalStateException(what);
                    NoClassDefFoundError cleanup = new NoClassDefFoundError(what);
                    if (inInitialize) {
                        fixture.hook(failing).onInitialize = () -> {
                            throw failure;
                        };
                    } else {
                        fixture.hook(failing).onReady = () -> {
                            throw failure;
                        };
                    }
                    fixture.hook(erring).onDrain = () -> {
                        throw cleanup;
                    };

                    assertThatThrownBy(fixture.composition::start).as(what).isSameAs(failure);

                    assertThat(fixture.snapshot()).as(what).containsExactlyElementsOf(expected);
                    assertThat(failure.getSuppressed()).as(what).containsExactly(cleanup);
                }
            }
        }
    }

    @Test
    @DisplayName("A drain that throws an exception during the unwind of a failed start is logged and goes no further: the start failure is thrown without suppressed, and the rest is drained and terminated")
    void drainExceptionDuringTheUnwindOfAFailedStart() {
        Fixture fixture = new Fixture();
        IllegalStateException failure = new IllegalStateException("ready D");
        fixture.hook("D").onReady = () -> {
            throw failure;
        };
        fixture.hook("C").onDrain = () -> {
            throw new IllegalStateException("drain C");
        };

        assertThatThrownBy(fixture.composition::start).isSameAs(failure);

        assertThat(failure.getSuppressed()).isEmpty();
        assertThat(fixture.snapshot()).containsExactlyElementsOf(expectedUnwind(3, false));
    }

    /** What a start failure and the cleanup's Errors must come to: the thrown Throwable and what it carries. */
    @Test
    @DisplayName("Precedence over every kind of start failure and cleanup Error: the start failure is thrown with the cleanup Error suppressed, except that a cleanup VirtualMachineError takes its place against a start failure that is not one")
    void precedenceOfTheStartFailureAndTheCleanup() {
        List<java.util.function.Supplier<Throwable>> starts = List.of(
                () -> new IllegalStateException("start"),
                () -> new NoClassDefFoundError("start"),
                () -> new StackOverflowError("start"));
        List<java.util.function.Supplier<Error>> ordinary = List.of(() -> new LinkageError("cleanup"));
        List<java.util.function.Supplier<Error>> fatal = List.of(() -> new OutOfMemoryError("cleanup"));

        for (int s = 0; s < starts.size(); s++) {
            for (String where : List.of("drain", "terminate")) {
                for (boolean isFatal : List.of(false, true)) {
                    Throwable start = starts.get(s).get();
                    Error cleanup = (isFatal ? fatal : ordinary).get(0).get();
                    String what = "start #" + s + ", " + (isFatal ? "fatal " : "ordinary ") + where;
                    Fixture fixture = new Fixture();
                    fixture.hook("D").onReady = () -> {
                        throw sneaky(start);
                    };
                    Action throwCleanup = () -> {
                        throw cleanup;
                    };
                    if (where.equals("drain")) {
                        fixture.hook("B").onDrain = throwCleanup;
                    } else {
                        fixture.hook("B").onTerminate = throwCleanup;
                    }

                    Throwable thrown = catchThrowable(fixture.composition::start);

                    boolean cleanupWins = isFatal && !(start instanceof VirtualMachineError);
                    if (cleanupWins) {
                        assertThat(thrown).as(what).isSameAs(cleanup);
                        assertThat(cleanup.getSuppressed()).as(what).containsExactly(start);
                        assertThat(start.getSuppressed()).as(what).isEmpty();
                    } else {
                        assertThat(thrown).as(what).isSameAs(start);
                        assertThat(start.getSuppressed()).as(what).containsExactly(cleanup);
                        assertThat(cleanup.getSuppressed()).as(what).isEmpty();
                    }
                    assertThat(fixture.snapshot()).as(what).containsExactlyElementsOf(expectedUnwind(3, false));
                }
            }
        }
    }

    @Test
    @DisplayName("Two cleanup Errors in one unwind: the first is kept with the later one suppressed on it, and the start failure carries that one; a cleanup VirtualMachineError after an ordinary Error takes the first place and carries it")
    void twoCleanupErrors() {
        Fixture ordinary = new Fixture();
        IllegalStateException failure = new IllegalStateException("ready D");
        NoClassDefFoundError firstCleanup = new NoClassDefFoundError("drain C");
        LinkageError secondCleanup = new LinkageError("terminate A");
        ordinary.hook("D").onReady = () -> {
            throw failure;
        };
        ordinary.hook("C").onDrain = () -> {
            throw firstCleanup;
        };
        ordinary.hook("A").onTerminate = () -> {
            throw secondCleanup;
        };

        assertThatThrownBy(ordinary.composition::start).isSameAs(failure);

        assertThat(failure.getSuppressed()).containsExactly(firstCleanup);
        assertThat(firstCleanup.getSuppressed()).containsExactly(secondCleanup);

        Fixture fatal = new Fixture();
        IllegalStateException failure2 = new IllegalStateException("ready D");
        NoClassDefFoundError earlier = new NoClassDefFoundError("drain C");
        OutOfMemoryError later = new OutOfMemoryError("terminate A");
        fatal.hook("D").onReady = () -> {
            throw failure2;
        };
        fatal.hook("C").onDrain = () -> {
            throw earlier;
        };
        fatal.hook("A").onTerminate = () -> {
            throw later;
        };

        assertThatThrownBy(fatal.composition::start).isSameAs(later);

        assertThat(later.getSuppressed()).hasSize(2).contains(failure2, earlier);
        assertThat(fatal.snapshot()).containsExactlyElementsOf(expectedUnwind(3, false));
    }

    @Test
    @DisplayName("Each capability drained by the unwind of a failed start is given a positive time within the 30 s composition-wide budget the conductor allows by default")
    void drainBudgetOfAFailedStart() {
        Fixture fixture = new Fixture();
        fixture.hook("C").onReady = () -> {
            throw new IllegalStateException("ready C");
        };

        assertThatThrownBy(fixture.composition::start).isInstanceOf(IllegalStateException.class);

        for (Hook hook : fixture.hooks) {
            assertThat(hook.drainBudgets).as(hook.name).hasSize(1);
            assertThat(hook.drainBudgets.get(0)).as(hook.name).isPositive().isLessThanOrEqualTo(Duration.ofSeconds(30));
        }
    }

    private static Throwable catchThrowable(Action action) {
        try {
            action.run();
            return null;
        } catch (Throwable thrown) {
            return thrown;
        }
    }

    @SuppressWarnings("unchecked")
    private static <T extends Throwable> RuntimeException sneaky(Throwable throwable) throws T {
        throw (T) throwable;
    }

    @Test
    @DisplayName("A drain that sleeps past the budget of a failed start is abandoned at the budget: the later drains are skipped as the budget is used up, every capability is terminated, and the start returns promptly")
    void overrunningDrainIsAbandoned() throws Exception {
        Fixture fixture = new Fixture();
        fixture.hook("D").onReady = () -> {
            throw new IllegalStateException("ready D");
        };
        fixture.hook("C").onDrain = () -> Thread.sleep(Duration.ofSeconds(120));
        ExecutorService pool = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "overrunning-start");
            thread.setDaemon(true);
            return thread;
        });
        try {
            long begin = System.nanoTime();
            Future<Object> starting = pool.submit(() -> catchThrowable(fixture.composition::start));

            Object outcome = starting.get(5 + 10, TimeUnit.SECONDS);
            long seconds = TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - begin);

            assertThat(outcome).isInstanceOf(IllegalStateException.class);
            assertThat(seconds).as("one budget of five seconds, not one per drain").isLessThan(8);
            assertThat(fixture.snapshot()).containsExactly("initialize:A", "initialize:B", "initialize:C",
                    "initialize:D", "ready:A", "ready:B", "ready:C", "ready:D", "drain:D", "drain:C",
                    "terminate:D", "terminate:C", "terminate:B", "terminate:A");
        } catch (TimeoutException hung) {
            throw new AssertionError("the unwind of a failed start was held by a drain that overran its budget; "
                    + "the log so far: " + fixture.snapshot(), hung);
        } finally {
            pool.shutdownNow();
        }
    }
}
