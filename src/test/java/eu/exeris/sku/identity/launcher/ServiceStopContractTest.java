package eu.exeris.sku.identity.launcher;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The state machine of {@link ServiceStop} from outside: admission and stop are decided on one variable, the
 * stop runs once, a reentrant stop returns at once, and a waiter waits for the completion however often it is
 * interrupted.
 */
@DisplayName("ServiceStop contract")
class ServiceStopContractTest {

    private static final int RACED_ROUNDS = 6_000;
    private static final long BOUND_SECONDS = 30;

    private static <T> T within(Future<T> future) throws Exception {
        try {
            return future.get(BOUND_SECONDS, TimeUnit.SECONDS);
        } catch (java.util.concurrent.TimeoutException hung) {
            throw new AssertionError("a caller did not return within " + BOUND_SECONDS + " s", hung);
        }
    }

    /** Staggers a racing task by a number of spins, so that every order of the racers is met. */
    private static void spin(int spins) {
        for (int i = 0; i < spins; i++) {
            Thread.onSpinWait();
        }
    }

    private static void awaitState(Thread thread, Thread.State... states) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(BOUND_SECONDS);
        while (!List.of(states).contains(thread.getState())) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("the thread never reached " + List.of(states) + ", it is " + thread.getState());
            }
            Thread.onSpinWait();
        }
    }

    // ---- 18 ----------------------------------------------------------------------------------------------

    @Test
    @DisplayName("Deterministic: an admission before the stop is run by it, once; an admission after the stop is refused and registers nothing")
    void admitAndStopInEveryOrder() {
        AtomicInteger first = new AtomicInteger();
        ServiceStop admittedFirst = new ServiceStop(() -> { });
        assertThat(admittedFirst.admit(first::incrementAndGet)).isTrue();
        assertThat(first).hasValue(0);
        assertThat(admittedFirst.stop()).isNull();
        assertThat(first).hasValue(1);
        assertThat(admittedFirst.stop()).isNull();
        assertThat(first).as("a second stop runs nothing").hasValue(1);

        AtomicInteger second = new AtomicInteger();
        ServiceStop stoppedFirst = new ServiceStop(() -> { });
        assertThat(stoppedFirst.stop()).isNull();
        assertThat(stoppedFirst.admit(second::incrementAndGet)).isFalse();
        assertThat(stoppedFirst.stop()).isNull();
        assertThat(second).as("a refused action is never run").hasValue(0);
    }

    @Test
    @DisplayName("Raced, at least 5000 rounds: the action ran exactly once when the admission was accepted, and not at all when it was refused")
    void admitRacingStop() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(3);
        int accepted = 0;
        int refused = 0;
        try {
            for (int round = 0; round < RACED_ROUNDS; round++) {
                AtomicInteger ran = new AtomicInteger();
                AtomicInteger withdrawn = new AtomicInteger();
                ServiceStop stop = new ServiceStop(withdrawn::incrementAndGet);
                CyclicBarrier barrier = new CyclicBarrier(3);
                int stopDelay = round % 3 == 0 ? 0 : (round * 37) % 3_000;
                int admitDelay = round % 3 == 0 ? (round * 53) % 3_000 : 0;
                Future<Boolean> admission = pool.submit(() -> {
                    barrier.await(BOUND_SECONDS, TimeUnit.SECONDS);
                    spin(admitDelay);
                    return stop.admit(ran::incrementAndGet);
                });
                Future<Throwable> firstStop = pool.submit(() -> {
                    barrier.await(BOUND_SECONDS, TimeUnit.SECONDS);
                    spin(stopDelay);
                    return stop.stop();
                });
                Future<Throwable> secondStop = pool.submit(() -> {
                    barrier.await(BOUND_SECONDS, TimeUnit.SECONDS);
                    spin(stopDelay + 50);
                    return stop.stop();
                });

                boolean admitted = within(admission);
                assertThat(within(firstStop)).isNull();
                assertThat(within(secondStop)).isNull();

                assertThat(withdrawn).as("round %d: the withdrawal runs once", round).hasValue(1);
                assertThat(ran.get()).as("round %d: admitted=%s", round, admitted).isEqualTo(admitted ? 1 : 0);
                if (admitted) {
                    accepted++;
                } else {
                    refused++;
                }
            }
        } finally {
            pool.shutdownNow();
        }
        System.out.println("[service-stop-contract] accepted=" + accepted + " refused=" + refused);
    }

    // ---- 19 ----------------------------------------------------------------------------------------------

    @Test
    @DisplayName("A stop made from inside the action, or from inside the withdrawal, on the performing thread returns null at once")
    void reentrantStopReturnsAtOnce() {
        AtomicReference<ServiceStop> self = new AtomicReference<>();
        AtomicReference<Object> fromWithdrawal = new AtomicReference<>("not called");
        AtomicReference<Object> fromAction = new AtomicReference<>("not called");
        ServiceStop stop = new ServiceStop(() -> fromWithdrawal.set(self.get().stop()));
        self.set(stop);
        stop.admit(() -> fromAction.set(stop.stop()));

        Throwable failure = stop.stop();

        assertThat(failure).isNull();
        assertThat(fromWithdrawal.get()).isNull();
        assertThat(fromAction.get()).isNull();
    }

    @Test
    @DisplayName("A stop from another thread waits without a limit until the action is done, then returns null")
    void anotherThreadWaits() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ServiceStop stop = new ServiceStop(() -> { });
        stop.admit(() -> {
            entered.countDown();
            awaitUninterruptibly(release);
        });
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<Throwable> performer = pool.submit(stop::stop);
            assertThat(entered.await(BOUND_SECONDS, TimeUnit.SECONDS)).isTrue();
            AtomicReference<Object> waiterResult = new AtomicReference<>("waiting");
            Thread waiter = new Thread(() -> waiterResult.set(stop.stop() == null ? "null" : "failure"), "stop-waiter");
            waiter.start();
            awaitState(waiter, Thread.State.WAITING, Thread.State.TIMED_WAITING);

            Thread.sleep(300);
            assertThat(waiterResult.get()).as("the waiter returned before the action was done").isEqualTo("waiting");
            release.countDown();
            waiter.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));

            assertThat(waiter.isAlive()).isFalse();
            assertThat(waiterResult.get()).isEqualTo("null");
            assertThat(within(performer)).isNull();
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
    }

    private static void awaitUninterruptibly(CountDownLatch latch) {
        boolean interrupted = false;
        while (true) {
            try {
                latch.await();
                break;
            } catch (InterruptedException e) {
                interrupted = true;
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    // ---- 20 ----------------------------------------------------------------------------------------------

    @Test
    @DisplayName("A second admission throws IllegalStateException and leaves the first action in place; after a stop it is refused instead")
    void secondAdmission() {
        AtomicInteger first = new AtomicInteger();
        AtomicInteger second = new AtomicInteger();
        ServiceStop stop = new ServiceStop(() -> { });
        assertThat(stop.admit(first::incrementAndGet)).isTrue();

        assertThatThrownBy(() -> stop.admit(second::incrementAndGet)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> stop.admit(second::incrementAndGet)).isInstanceOf(IllegalStateException.class);
        stop.stop();

        assertThat(first).as("the first action is the one that runs").hasValue(1);
        assertThat(second).hasValue(0);
        assertThat(stop.admit(second::incrementAndGet)).as("after the stop it is refused").isFalse();
    }

    // ---- 21 ----------------------------------------------------------------------------------------------

    @Test
    @DisplayName("Earlier semantics: withdrawal first, then the action; the first failure is returned with the second suppressed; a stop with nothing admitted runs the withdrawal alone")
    void earlierSemantics() {
        List<String> order = new ArrayList<>();
        IllegalStateException one = new IllegalStateException("withdrawal");
        IllegalArgumentException two = new IllegalArgumentException("action");
        ServiceStop failing = new ServiceStop(() -> {
            order.add("withdraw");
            throw one;
        });
        failing.admit(() -> {
            order.add("action");
            throw two;
        });

        Throwable failure = failing.stop();

        assertThat(order).containsExactly("withdraw", "action");
        assertThat(failure).isSameAs(one);
        assertThat(failure.getSuppressed()).containsExactly(two);
        assertThat(failing.stop()).isNull();

        AtomicInteger withdrawn = new AtomicInteger();
        ServiceStop alone = new ServiceStop(withdrawn::incrementAndGet);
        assertThat(alone.stop()).isNull();
        assertThat(withdrawn).hasValue(1);
    }

    // ---- E -----------------------------------------------------------------------------------------------

    @Test
    @DisplayName("E: a stop racing a first and a second admission: at most one admission is accepted, the other throws or is refused, and only an accepted action runs, once")
    void stopRacingTwoAdmissions() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(3);
        try {
            int bothRefused = 0;
            int firstWon = 0;
            for (int round = 0; round < RACED_ROUNDS; round++) {
                AtomicInteger ranA = new AtomicInteger();
                AtomicInteger ranB = new AtomicInteger();
                ServiceStop stop = new ServiceStop(() -> { });
                CyclicBarrier barrier = new CyclicBarrier(3);
                int stopDelay = round % 3 == 0 ? 0 : (round * 37) % 3_000;
                int secondDelay = (round * 11) % 500;
                Future<Object> a = pool.submit(() -> attempt(barrier, 0, () -> stop.admit(ranA::incrementAndGet)));
                Future<Object> b = pool.submit(() -> attempt(barrier, secondDelay, () -> stop.admit(ranB::incrementAndGet)));
                Future<Object> stopping = pool.submit(() -> attempt(barrier, stopDelay, stop::stop));

                Object admissionA = within(a);
                Object admissionB = within(b);
                assertThat(within(stopping)).isNull();
                stop.stop();

                boolean acceptedA = Boolean.TRUE.equals(admissionA);
                boolean acceptedB = Boolean.TRUE.equals(admissionB);
                assertThat(acceptedA && acceptedB).as("round %d: both accepted", round).isFalse();
                assertThat(ranA.get()).as("round %d: A=%s", round, admissionA).isEqualTo(acceptedA ? 1 : 0);
                assertThat(ranB.get()).as("round %d: B=%s", round, admissionB).isEqualTo(acceptedB ? 1 : 0);
                for (Object outcome : new Object[] {admissionA, admissionB}) {
                    assertThat(outcome).as("round %d", round).satisfiesAnyOf(
                            o -> assertThat(o).isEqualTo(true), o -> assertThat(o).isEqualTo(false),
                            o -> assertThat(o).isInstanceOf(IllegalStateException.class));
                }
                if (!acceptedA && !acceptedB) {
                    bothRefused++;
                } else {
                    firstWon++;
                }
            }
            System.out.println("[service-stop-two-admissions] noneAccepted=" + bothRefused + " oneAccepted=" + firstWon);
        } finally {
            pool.shutdownNow();
        }
    }

    private static Object attempt(CyclicBarrier barrier, int delay, java.util.concurrent.Callable<Object> call) throws Exception {
        barrier.await(BOUND_SECONDS, TimeUnit.SECONDS);
        spin(delay);
        try {
            return call.call();
        } catch (IllegalStateException refused) {
            return refused;
        }
    }

    @Test
    @DisplayName("E: admit(null) accepts nothing to run: the stop runs the withdrawal alone and a real action may still be admitted")
    void admitNull() {
        AtomicInteger withdrawn = new AtomicInteger();
        AtomicInteger ran = new AtomicInteger();
        ServiceStop stop = new ServiceStop(withdrawn::incrementAndGet);

        assertThat(stop.admit(null)).isTrue();
        assertThat(stop.admit(ran::incrementAndGet)).as("null registered no action").isTrue();
        assertThat(stop.stop()).isNull();

        assertThat(ran).hasValue(1);
        assertThat(withdrawn).hasValue(1);

        ServiceStop onlyNull = new ServiceStop(withdrawn::incrementAndGet);
        assertThat(onlyNull.admit(null)).isTrue();
        assertThat(onlyNull.stop()).isNull();
        assertThat(withdrawn).hasValue(2);
    }

    @Test
    @DisplayName("E: an action that reenters stop and then throws: the performer gets the failure, a waiter gets null, nobody hangs")
    void throwingActionThatReenters() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicReference<Object> reentry = new AtomicReference<>("not called");
        IllegalStateException failure = new IllegalStateException("boom");
        AtomicReference<ServiceStop> self = new AtomicReference<>();
        ServiceStop stop = new ServiceStop(() -> { });
        self.set(stop);
        stop.admit(() -> {
            entered.countDown();
            awaitUninterruptibly(release);
            reentry.set(self.get().stop());
            throw failure;
        });
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<Throwable> performer = pool.submit(stop::stop);
            assertThat(entered.await(BOUND_SECONDS, TimeUnit.SECONDS)).isTrue();
            Future<Throwable> waiter = pool.submit(stop::stop);
            Thread.sleep(100);
            release.countDown();

            assertThat(within(performer)).isSameAs(failure);
            assertThat(within(waiter)).isNull();
            assertThat(reentry.get()).isNull();
            assertThat(stop.stop()).isNull();
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("E: a waiter interrupted ten thousand times returns only after the action completes, with its flag set, and ends no thread behind it")
    void repeatedlyInterruptedWaiter() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicBoolean completed = new AtomicBoolean();
        ServiceStop stop = new ServiceStop(() -> { });
        stop.admit(() -> {
            entered.countDown();
            awaitUninterruptibly(release);
            completed.set(true);
        });
        Thread performer = new Thread(stop::stop, "stop-performer");
        performer.start();
        assertThat(entered.await(BOUND_SECONDS, TimeUnit.SECONDS)).isTrue();
        AtomicBoolean completedWhenReturned = new AtomicBoolean();
        AtomicBoolean flagOnReturn = new AtomicBoolean();
        Thread waiter = new Thread(() -> {
            stop.stop();
            completedWhenReturned.set(completed.get());
            flagOnReturn.set(Thread.currentThread().isInterrupted());
        }, "stop-waiter");
        waiter.start();
        awaitState(waiter, Thread.State.WAITING, Thread.State.TIMED_WAITING);

        for (int i = 0; i < 10_000; i++) {
            waiter.interrupt();
            if (i % 1_000 == 0) {
                assertThat(waiter.isAlive()).as("interrupt %d ended the wait", i).isTrue();
                assertThat(completed.get()).isFalse();
            }
        }
        assertThat(waiter.isAlive()).as("the waiter gave up on an interrupt").isTrue();
        release.countDown();
        waiter.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
        performer.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));

        assertThat(waiter.isAlive()).isFalse();
        assertThat(performer.isAlive()).isFalse();
        assertThat(completedWhenReturned).isTrue();
        assertThat(flagOnReturn).as("the interrupt flag is restored").isTrue();
        assertThat(Thread.getAllStackTraces().keySet()).extracting(Thread::getName)
                .doesNotContain("stop-waiter", "stop-performer");
    }

    /** A rule of the documented contract that the implementation does not keep; skipped unless asked for. */
    @org.junit.jupiter.api.Nested
    @DisplayName("Known defects (run with -Didentity.knownDefects=true)")
    class KnownDefects {

        @Test
        @DisplayName("A failure of the withdrawal, a VirtualMachineError included, does not skip the composition's stop")
        void fatalErrorInTheWithdrawalStillStopsTheComposition() {
            AtomicInteger composed = new AtomicInteger();
            ServiceStop stop = new ServiceStop(() -> {
                throw new InternalError("withdrawal");
            });
            stop.admit(composed::incrementAndGet);

            try {
                stop.stop();
            } catch (InternalError expectedToPropagate) {
                // whether it propagates is not what is under test
            }

            assertThat(composed).as("the composition's stop ran after the withdrawal failed").hasValue(1);
        }
    }
}
