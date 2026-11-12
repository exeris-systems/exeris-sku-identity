package eu.exeris.sku.identity.launcher;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The stop of a served composition, with no kernel. Every interleaving is forced by latches, by a barrier
 * that releases the contending threads together, or by observing a thread's state; no test waits for time to
 * pass in order to be right.
 */
@DisplayName("ServiceStop")
class ServiceStopTest {

    private static final int ROUNDS = 2_000;
    private static final int CALLERS = 8;
    private static final long BOUND_SECONDS = 20;

    /** Everything a round records, in the order it happened. */
    private static final class Events {
        final ConcurrentLinkedQueue<String> log = new ConcurrentLinkedQueue<>();
        final AtomicInteger withdrawn = new AtomicInteger();
        final AtomicInteger composed = new AtomicInteger();

        Runnable withdraw() {
            return () -> {
                withdrawn.incrementAndGet();
                log.add("withdraw");
            };
        }

        Runnable composition() {
            return () -> {
                composed.incrementAndGet();
                log.add("composition");
            };
        }
    }

    private static <T> T within(Future<T> future) throws Exception {
        try {
            return future.get(BOUND_SECONDS, TimeUnit.SECONDS);
        } catch (TimeoutException hung) {
            throw new AssertionError("a caller did not return within " + BOUND_SECONDS + " s", hung);
        }
    }

    /** Runs the tasks together on a barrier and returns what each returned, in order. */
    private static <T> List<T> together(ExecutorService pool, List<Callable<T>> tasks) throws Exception {
        CyclicBarrier barrier = new CyclicBarrier(tasks.size());
        List<Future<T>> futures = new ArrayList<>();
        for (Callable<T> task : tasks) {
            futures.add(pool.submit(() -> {
                barrier.await(BOUND_SECONDS, TimeUnit.SECONDS);
                return task.call();
            }));
        }
        List<T> results = new ArrayList<>();
        for (Future<T> future : futures) {
            results.add(within(future));
        }
        return results;
    }

    /** Polls an observable condition; the bound only turns a condition that never holds into a failure. */
    private static void awaitCondition(String what, java.util.function.BooleanSupplier condition) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(BOUND_SECONDS);
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("never observed: " + what);
            }
            Thread.onSpinWait();
        }
    }

    private static boolean waiting(Thread thread) {
        return thread.getState() == Thread.State.WAITING || thread.getState() == Thread.State.TIMED_WAITING;
    }

    // ---- 1 ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("Eight threads stopping together run the withdrawal once, the composition's stop once, in that order")
    void concurrentStopsRunEachActionOnce() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(CALLERS);
        try {
            for (int round = 0; round < ROUNDS; round++) {
                Events events = new Events();
                ServiceStop stop = new ServiceStop(events.withdraw());
                assertThat(stop.admit(events.composition())).isTrue();
                List<Callable<Throwable>> tasks = new ArrayList<>();
                for (int i = 0; i < CALLERS; i++) {
                    tasks.add(stop::stop);
                }

                List<Throwable> failures = together(pool, tasks);

                assertThat(failures).as("round %d", round).containsOnlyNulls();
                assertThat(events.log).as("round %d", round).containsExactly("withdraw", "composition");
            }
        } finally {
            pool.shutdownNow();
        }
    }

    // ---- 2 ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("No caller, the one that performs the stop or one that waits for it, returns before the action completes")
    void nobodyReturnsBeforeCompletion() throws Exception {
        for (int round = 0; round < 300; round++) {
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            AtomicBoolean completed = new AtomicBoolean();
            ServiceStop stop = new ServiceStop(() -> { });
            stop.admit(() -> {
                entered.countDown();
                try {
                    release.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                completed.set(true);
            });
            AtomicInteger arrived = new AtomicInteger();
            AtomicInteger returned = new AtomicInteger();
            AtomicInteger returnedEarly = new AtomicInteger();
            List<Thread> callers = new ArrayList<>();
            for (int i = 0; i < CALLERS; i++) {
                Thread caller = new Thread(() -> {
                    arrived.incrementAndGet();
                    stop.stop();
                    if (!completed.get()) {
                        returnedEarly.incrementAndGet();
                    }
                    returned.incrementAndGet();
                }, "caller-" + i);
                callers.add(caller);
                caller.start();
            }

            assertThat(entered.await(BOUND_SECONDS, TimeUnit.SECONDS)).isTrue();
            awaitCondition("all callers arrived", () -> arrived.get() == CALLERS);
            // After arriving a caller can only be inside stop(): running, or blocked on the action or the latch.
            awaitCondition("every caller blocked inside stop()", () -> callers.stream().allMatch(
                    c -> waiting(c)));
            assertThat(returned.get()).as("callers that returned while the action was still running").isZero();

            release.countDown();
            for (Thread caller : callers) {
                caller.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
                assertThat(caller.isAlive()).isFalse();
            }
            assertThat(returned.get()).isEqualTo(CALLERS);
            assertThat(returnedEarly.get()).isZero();
        }
    }

    // ---- 3 ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("A throwing withdrawal does not skip the composition's stop; the first failure is returned and carries the second")
    void throwingWithdrawalDoesNotSkipTheComposition() {
        IllegalStateException first = new IllegalStateException("withdrawal");
        IllegalArgumentException second = new IllegalArgumentException("composition");
        AtomicInteger composed = new AtomicInteger();
        ServiceStop stop = new ServiceStop(() -> {
            throw first;
        });
        stop.admit(() -> {
            composed.incrementAndGet();
            throw second;
        });

        Throwable failure = stop.stop();

        assertThat(composed).hasValue(1);
        assertThat(failure).isSameAs(first);
        assertThat(failure.getSuppressed()).containsExactly(second);
    }

    @Test
    @DisplayName("A withdrawal that throws an Error and a composition that succeeds: the composition still stops, the Error is returned")
    void throwingWithdrawalWithSucceedingComposition() {
        AssertionError first = new AssertionError("withdrawal");
        AtomicInteger composed = new AtomicInteger();
        ServiceStop stop = new ServiceStop(() -> {
            throw first;
        });
        stop.admit(composed::incrementAndGet);

        assertThat(stop.stop()).isSameAs(first);
        assertThat(composed).hasValue(1);
        assertThat(first.getSuppressed()).isEmpty();
    }

    @Test
    @DisplayName("A succeeding withdrawal and a throwing composition: the composition's failure is returned, nothing suppressed")
    void throwingCompositionAlone() {
        IllegalStateException failure = new IllegalStateException("composition");
        ServiceStop stop = new ServiceStop(() -> { });
        stop.admit(() -> {
            throw failure;
        });

        assertThat(stop.stop()).isSameAs(failure);
        assertThat(failure.getSuppressed()).isEmpty();
    }

    // ---- 4 ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("When the action throws exactly one caller receives the failure, the others get null, and nobody hangs")
    void aThrowingActionIsReportedToOneCaller() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(CALLERS);
        try {
            for (int round = 0; round < ROUNDS; round++) {
                IllegalStateException failure = new IllegalStateException("round " + round);
                ServiceStop stop = new ServiceStop(() -> { });
                stop.admit(() -> {
                    throw failure;
                });
                List<Callable<Throwable>> tasks = new ArrayList<>();
                for (int i = 0; i < CALLERS; i++) {
                    tasks.add(stop::stop);
                }

                List<Throwable> results = together(pool, tasks);

                assertThat(results).as("round %d", round).filteredOn(r -> r != null).containsExactly(failure);
                assertThat(results).hasSize(CALLERS);
            }
        } finally {
            pool.shutdownNow();
        }
    }

    // ---- 5 ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("A stop before the admission refuses it and the action never runs; an admission and then a stop runs it once")
    void stopBeforeAndAfterAdmission() {
        Events early = new Events();
        ServiceStop stoppedFirst = new ServiceStop(early.withdraw());
        assertThat(stoppedFirst.stop()).isNull();

        assertThat(stoppedFirst.admit(early.composition())).isFalse();
        assertThat(stoppedFirst.stop()).isNull();
        assertThat(early.composed).hasValue(0);
        assertThat(early.withdrawn).hasValue(1);

        Events late = new Events();
        ServiceStop admittedFirst = new ServiceStop(late.withdraw());
        assertThat(admittedFirst.admit(late.composition())).isTrue();
        assertThat(admittedFirst.stop()).isNull();
        assertThat(late.log).containsExactly("withdraw", "composition");
    }

    @Test
    @DisplayName("A stop with nothing admitted runs the withdrawal alone")
    void stopWithNothingAdmitted() {
        Events events = new Events();
        ServiceStop stop = new ServiceStop(events.withdraw());

        assertThat(stop.stop()).isNull();

        assertThat(events.log).containsExactly("withdraw");
    }

    // ---- 6 ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("Racing the admission against the stop: either the action ran once or the admission was refused, never neither and never both")
    void admissionRacingTheStop() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        int neither = 0;
        int both = 0;
        try {
            for (int round = 0; round < ROUNDS; round++) {
                Events events = new Events();
                ServiceStop stop = new ServiceStop(events.withdraw());
                List<Callable<Object>> tasks = List.of(
                        () -> stop.admit(events.composition()),
                        () -> stop.stop());

                List<Object> results = together(pool, tasks);
                boolean admitted = (Boolean) results.get(0);
                int ran = events.composed.get();

                assertThat(events.withdrawn).as("round %d", round).hasValue(1);
                assertThat(ran).as("round %d: the action ran more than once", round).isLessThanOrEqualTo(1);
                if (admitted && ran == 0) {
                    neither++;
                }
                if (!admitted && ran == 1) {
                    both++;
                }
            }
        } finally {
            pool.shutdownNow();
        }
        assertThat(neither).as("rounds in which the admission succeeded and nobody ran the action").isZero();
        assertThat(both).as("rounds in which the admission was refused and the action ran anyway").isZero();
    }

    @Test
    @DisplayName("An admission that is refused because a stop has begun does not register an action that the stop then runs")
    void refusedAdmissionRegistersNothing() throws Exception {
        Events events = new Events();
        CountDownLatch withdrawing = new CountDownLatch(1);
        CountDownLatch proceed = new CountDownLatch(1);
        ServiceStop stop = new ServiceStop(() -> {
            withdrawing.countDown();
            try {
                proceed.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<Throwable> stopping = pool.submit(stop::stop);
            assertThat(withdrawing.await(BOUND_SECONDS, TimeUnit.SECONDS)).isTrue();

            boolean admitted = stop.admit(events.composition());
            proceed.countDown();
            within(stopping);

            assertThat(admitted).isFalse();
            assertThat(events.composed.get()).as("the action of a refused admission ran").isZero();
        } finally {
            pool.shutdownNow();
        }
    }

    // ---- 7 ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("A waiter that is interrupted keeps waiting, returns only after completion and returns with its interrupt flag set")
    void interruptedWaiter() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicBoolean completed = new AtomicBoolean();
        ServiceStop stop = new ServiceStop(() -> { });
        stop.admit(() -> {
            entered.countDown();
            try {
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            completed.set(true);
        });
        ExecutorService performerPool = Executors.newSingleThreadExecutor();
        AtomicReference<Boolean> completedOnReturn = new AtomicReference<>();
        AtomicReference<Boolean> flagOnReturn = new AtomicReference<>();
        AtomicReference<Throwable> waiterResult = new AtomicReference<>(new Error("not returned"));
        AtomicBoolean waiterReturned = new AtomicBoolean();
        try {
            Future<Throwable> performer = performerPool.submit(stop::stop);
            assertThat(entered.await(BOUND_SECONDS, TimeUnit.SECONDS)).isTrue();
            Thread waiter = new Thread(() -> {
                waiterResult.set(stop.stop());
                completedOnReturn.set(completed.get());
                flagOnReturn.set(Thread.currentThread().isInterrupted());
                waiterReturned.set(true);
            }, "waiter");
            waiter.start();
            awaitCondition("the waiter is blocked", () -> waiting(waiter));

            waiter.interrupt();
            // The interrupt is consumed by the wait, and the waiter goes back to waiting.
            awaitCondition("the waiter consumed the interrupt and waits again",
                    () -> !waiter.isInterrupted() && waiting(waiter));
            assertThat(waiterReturned.get()).as("the waiter returned although the action was still running").isFalse();

            release.countDown();
            waiter.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
            within(performer);

            assertThat(waiter.isAlive()).isFalse();
            assertThat(completedOnReturn.get()).isTrue();
            assertThat(flagOnReturn.get()).as("interrupt flag on return").isTrue();
            assertThat(waiterResult.get()).isNull();
        } finally {
            performerPool.shutdownNow();
        }
    }

    // ---- 8 ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("A second stop after completion returns null at once and runs nothing")
    void stopAfterCompletion() throws Exception {
        Events events = new Events();
        ServiceStop stop = new ServiceStop(events.withdraw());
        stop.admit(events.composition());
        assertThat(stop.stop()).isNull();
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<Throwable> second = pool.submit(stop::stop);

            assertThat(within(second)).isNull();
            assertThat(events.log).containsExactly("withdraw", "composition");
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("A second stop after a failed one returns null: the failure is reported once")
    void failureIsReportedOnce() {
        IllegalStateException failure = new IllegalStateException("once");
        ServiceStop stop = new ServiceStop(() -> { });
        stop.admit(() -> {
            throw failure;
        });

        assertThat(stop.stop()).isSameAs(failure);
        assertThat(stop.stop()).isNull();
    }

    // ---- 9 ---------------------------------------------------------------------------------------------

    @Test
    @DisplayName("An InternalError in the action releases every waiter and propagates out of the performer's stop")
    void virtualMachineErrorInTheAction() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        InternalError fatal = new InternalError("fatal");
        ServiceStop stop = new ServiceStop(() -> { });
        stop.admit(() -> {
            entered.countDown();
            try {
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            throw fatal;
        });
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            Future<Throwable> performer = pool.submit(stop::stop);
            assertThat(entered.await(BOUND_SECONDS, TimeUnit.SECONDS)).isTrue();
            List<Thread> waiters = new ArrayList<>();
            List<AtomicReference<Object>> outcomes = new ArrayList<>();
            for (int i = 0; i < 3; i++) {
                AtomicReference<Object> outcome = new AtomicReference<>("not returned");
                Thread waiter = new Thread(() -> outcome.set(stop.stop() == null ? "null" : "failure"), "waiter-" + i);
                outcomes.add(outcome);
                waiters.add(waiter);
                waiter.start();
            }
            awaitCondition("the waiters are blocked", () -> waiters.stream().allMatch(ServiceStopTest::waiting));

            release.countDown();
            for (Thread waiter : waiters) {
                waiter.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
                assertThat(waiter.isAlive()).as("a waiter was not released").isFalse();
            }

            assertThat(outcomes).extracting(AtomicReference::get).containsOnly("null");
            try {
                performer.get(BOUND_SECONDS, TimeUnit.SECONDS);
                throw new AssertionError("the performer returned instead of rethrowing the InternalError");
            } catch (ExecutionException e) {
                assertThat(e.getCause()).isSameAs(fatal);
            }
            assertThat(stop.stop()).isNull();
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("An InternalError in the withdrawal propagates to the performer and the stop is still complete for later callers")
    void virtualMachineErrorInTheWithdrawal() {
        InternalError fatal = new InternalError("fatal");
        ServiceStop stop = new ServiceStop(() -> {
            throw fatal;
        });
        stop.admit(() -> { });

        try {
            stop.stop();
            throw new AssertionError("the performer returned instead of rethrowing the InternalError");
        } catch (InternalError thrown) {
            assertThat(thrown).isSameAs(fatal);
        }

        assertThat(stop.stop()).isNull();
    }

    // ---- 10 --------------------------------------------------------------------------------------------

    @Test
    @DisplayName("An action that re-enters stop() on the same object does not deadlock")
    void reentrantStopDoesNotDeadlock() throws Exception {
        AtomicBoolean reentryReturned = new AtomicBoolean();
        AtomicBoolean performed = new AtomicBoolean();
        ServiceStop[] holder = new ServiceStop[1];
        holder[0] = new ServiceStop(() -> { });
        holder[0].admit(() -> {
            holder[0].stop();
            reentryReturned.set(true);
        });
        Thread performer = new Thread(() -> {
            holder[0].stop();
            performed.set(true);
        }, "reentrant-performer");
        performer.setDaemon(true);

        performer.start();
        performer.join(TimeUnit.SECONDS.toMillis(5));

        assertThat(performer.isAlive()).as("the performer is stuck in the re-entrant call: " + Thread.State.WAITING
                + " " + java.util.Arrays.toString(performer.getStackTrace())).isFalse();
        assertThat(reentryReturned.get()).isTrue();
        assertThat(performed.get()).isTrue();
    }
}
