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
    @DisplayName("A start whose ready throws terminates what was initialised, ends stopped, refuses start and tryStart, and a stop does nothing")
    void failedStartInReady() {
        Fixture fixture = new Fixture();
        IllegalStateException failure = new IllegalStateException("ready C");
        fixture.hook("C").onReady = () -> {
            throw failure;
        };

        assertThatThrownBy(fixture.composition::start).isSameAs(failure);

        List<String> expected = List.of("initialize:A", "initialize:B", "initialize:C", "initialize:D",
                "ready:A", "ready:B", "ready:C", "terminate:D", "terminate:C", "terminate:B", "terminate:A");
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
    @DisplayName("A start whose initialize throws terminates the capabilities initialised before it and touches none after it")
    void failedStartInInitialize() {
        Fixture fixture = new Fixture();
        fixture.hook("C").onInitialize = () -> {
            throw new IllegalStateException("initialize C");
        };

        assertThatThrownBy(fixture.composition::start).isInstanceOf(IllegalStateException.class);

        assertThat(fixture.snapshot()).containsExactly("initialize:A", "initialize:B", "initialize:C",
                "terminate:B", "terminate:A");
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
}
