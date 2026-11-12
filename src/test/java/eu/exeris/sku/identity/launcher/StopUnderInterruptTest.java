package eu.exeris.sku.identity.launcher;

import eu.exeris.caps.serviceboundarycore.ServiceBoundaryCoreModule;
import eu.exeris.kernel.community.security.Argon2idPasswordEncoder;
import eu.exeris.kernel.spi.security.credentials.PasswordEncoderConfig;
import eu.exeris.sdk.composition.lifecycle.CapabilityLifecycleHooks;
import eu.exeris.sku.identity.IdentityComposition;
import eu.exeris.sku.identity.IdentityServices;
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

import java.lang.reflect.Constructor;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The stop of the launcher under an interrupt of the thread that performs it: the composition's drain and
 * terminate hooks run through {@link ServiceStop} on a thread that stands for the serving thread. The
 * capabilities are recording doubles; there is no database and no kernel.
 */
@DisplayName("ServiceStop and the composition under an interrupt of the performing thread")
class StopUnderInterruptTest {

    private static final long BOUND_SECONDS = 60;
    private static final Duration BUDGET = Duration.ofMillis(400);

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

    private static final class Cap implements CapabilityLifecycleHooks {
        final String name;
        final List<String> log;
        volatile Action onDrain = () -> { };
        final List<Boolean> flagSeenByTerminate = new java.util.concurrent.CopyOnWriteArrayList<>();

        Cap(String name, List<String> log) {
            this.name = name;
            this.log = log;
        }

        @Override
        public void drain(Duration timeout) throws Exception {
            log.add("drain:" + name);
            onDrain.run();
        }

        @Override
        public void terminate() {
            log.add("terminate:" + name);
            flagSeenByTerminate.add(Thread.currentThread().isInterrupted());
        }
    }

    private static final class Fixture {
        final List<String> log = Collections.synchronizedList(new ArrayList<>());
        final List<Cap> caps = List.of(new Cap("A", log), new Cap("B", log), new Cap("C", log), new Cap("D", log));
        final IdentityComposition composition;

        Fixture() throws Exception {
            composition = constructor.newInstance(boundary, new ArrayList<CapabilityLifecycleHooks>(caps),
                    base.jwtAdmissionPolicy(), base.jwtBinding(), base.services());
            composition.start();
        }

        List<String> entries(String kind) {
            synchronized (log) {
                return log.stream().filter(e -> e.startsWith(kind + ":")).toList();
            }
        }
    }

    private record Ran(Throwable thrown, Throwable stopFailure, boolean flagAfter) {
    }

    /** Runs the action on a thread standing for the serving thread; the action returns the stop's failure. */
    private static Ran onThread(boolean flagOnEntry, Callable<Throwable> action) throws Exception {
        Object[] box = new Object[3];
        Thread thread = new Thread(() -> {
            if (flagOnEntry) {
                Thread.currentThread().interrupt();
            }
            try {
                box[1] = action.call();
            } catch (Throwable thrown) {
                box[0] = thrown;
            }
            box[2] = Thread.currentThread().isInterrupted();
        }, "serving-thread");
        thread.setDaemon(true);
        thread.start();
        thread.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
        if (thread.isAlive()) {
            thread.interrupt();
            throw new AssertionError("the call did not return within " + BOUND_SECONDS + " s");
        }
        return new Ran((Throwable) box[0], (Throwable) box[1], (Boolean) box[2]);
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

    private static Thread watchdog() {
        List<Thread> found = Thread.getAllStackTraces().keySet().stream()
                .filter(t -> t.getName().equals("identity-drain-watchdog") && t.isAlive()).toList();
        if (found.size() != 1) {
            throw new AssertionError("expected one watchdog, found " + found.size());
        }
        return found.get(0);
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

    @Test
    @DisplayName("A performer whose flag is set on entry stops the composition, gets no failure back, and still has the flag set")
    void performerWithTheFlagSet() throws Exception {
        Fixture fixture = new Fixture();
        ServiceStop stop = new ServiceStop(() -> { });
        assertThat(stop.admit(() -> fixture.composition.stop(BUDGET))).isTrue();

        Ran ran = onThread(true, stop::stop);

        assertThat(ran.thrown()).isNull();
        assertThat(ran.stopFailure()).isNull();
        assertThat(ran.flagAfter()).isTrue();
        assertThat(fixture.entries("drain")).containsExactly("drain:D", "drain:C", "drain:B", "drain:A");
        assertThat(fixture.entries("terminate")).containsExactly("terminate:D", "terminate:C", "terminate:B", "terminate:A");
    }

    @Test
    @DisplayName("A waiter whose flag is set waits until the performer has finished, and has the flag set when it returns")
    void waiterWithTheFlagSet() throws Exception {
        CountDownLatch inside = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ServiceStop stop = new ServiceStop(() -> { });
        assertThat(stop.admit(() -> {
            inside.countDown();
            try {
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        })).isTrue();
        Thread performer = new Thread(stop::stop, "performer");
        performer.setDaemon(true);
        performer.start();
        assertThat(inside.await(30, TimeUnit.SECONDS)).isTrue();
        long[] returnedAt = new long[1];
        long releasedAt = 0;
        Thread waiterThread;
        Object[] box = new Object[2];
        waiterThread = new Thread(() -> {
            Thread.currentThread().interrupt();
            box[0] = stop.stop();
            returnedAt[0] = System.nanoTime();
            box[1] = Thread.currentThread().isInterrupted();
        }, "waiter");
        waiterThread.setDaemon(true);
        waiterThread.start();
        waiterThread.join(300);
        assertThat(waiterThread.isAlive()).as("the waiter keeps waiting although its flag is set").isTrue();
        releasedAt = System.nanoTime();
        release.countDown();
        waiterThread.join(TimeUnit.SECONDS.toMillis(30));
        assertThat(waiterThread.isAlive()).isFalse();
        assertThat(box[0]).isNull();
        assertThat(box[1]).isEqualTo(true);
        assertThat(returnedAt[0]).isGreaterThanOrEqualTo(releasedAt);
    }

    /**
     * The serving thread of the launcher performs the stop with its flag clear only when the service failed
     * (the {@code finally} of the callback). A third party interrupt that coalesces with the watchdog's
     * while an overrunning drain is abandoned is lost; the stop still completes, hands back no failure and
     * terminates everything, and the ending, and so the exit status, is decided by the recorded outcome and
     * not by the flag.
     */
    @Test
    @DisplayName("Characterisation: a failed service stops on the serving thread, a third party interrupt coalesces with the watchdog's during an overrunning drain and is lost; the stop completes and the status is that of the failure")
    void lostInterruptOnTheServingThreadOfAFailedService() throws Exception {
        Fixture fixture = new Fixture();
        CountDownLatch fired = new CountDownLatch(1);
        CountDownLatch sent = new CountDownLatch(1);
        Thread[] serving = new Thread[1];
        fixture.caps.get(3).onDrain = () -> {
            serving[0] = Thread.currentThread();
            spinUntilEnded(watchdog());
            fired.countDown();
            spinUntil(sent);
        };
        Thread thirdParty = new Thread(() -> {
            try {
                fired.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                return;
            }
            serving[0].interrupt();
            sent.countDown();
        }, "host");
        thirdParty.setDaemon(true);
        thirdParty.start();
        ServiceStop stop = new ServiceStop(() -> { });
        assertThat(stop.admit(() -> fixture.composition.stop(BUDGET))).isTrue();

        Ran ran = onThread(false, stop::stop);

        assertThat(sent.getCount()).isZero();
        assertThat(ran.thrown()).isNull();
        assertThat(ran.stopFailure()).isNull();
        assertThat(fixture.entries("terminate")).containsExactly("terminate:D", "terminate:C", "terminate:B", "terminate:A");
        assertThat(ran.flagAfter()).as("characterisation: the host's request is lost").isFalse();
        assertThat(IdentitySkuApplication.exitStatus(IdentitySkuApplication.Ending.SERVICE_FAILED))
                .as("the status of a failed service does not read the flag")
                .isEqualTo(IdentitySkuApplication.exitStatus(IdentitySkuApplication.Ending.KERNEL_NOT_BOOTED));
    }

    @Test
    @DisplayName("A host that interrupts the serving thread to stop it, and interrupts it again while a drain overruns: the flag was set on entry to the stop, the second interrupt coalesces and the flag is still set on return")
    void secondInterruptOfAnImpatientHost() throws Exception {
        Fixture fixture = new Fixture();
        CountDownLatch fired = new CountDownLatch(1);
        CountDownLatch sent = new CountDownLatch(1);
        Thread[] serving = new Thread[1];
        fixture.caps.get(3).onDrain = () -> {
            serving[0] = Thread.currentThread();
            spinUntilEnded(watchdog());
            fired.countDown();
            spinUntil(sent);
        };
        Thread thirdParty = new Thread(() -> {
            try {
                fired.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                return;
            }
            serving[0].interrupt();
            sent.countDown();
        }, "host");
        thirdParty.setDaemon(true);
        thirdParty.start();
        ServiceStop stop = new ServiceStop(() -> { });
        assertThat(stop.admit(() -> fixture.composition.stop(BUDGET))).isTrue();

        Ran ran = onThread(true, stop::stop);

        assertThat(ran.thrown()).isNull();
        assertThat(ran.stopFailure()).isNull();
        assertThat(ran.flagAfter()).isTrue();
        assertThat(fixture.entries("terminate")).hasSize(4);
    }
}
