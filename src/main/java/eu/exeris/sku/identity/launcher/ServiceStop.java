package eu.exeris.sku.identity.launcher;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The one place a served composition is stopped. The thread that finishes serving and the shutdown hook
 * both ask; one of them performs the stop and the other waits for it.
 *
 * <p>Invariants:
 * <ul>
 *   <li>The stop actions run at most once, however many threads call {@link #stop()}: the first caller wins
 *       a compare-and-set and is the only one that runs them.</li>
 *   <li>Every call of {@link #stop()} returns only after the actions have completed, whether it performed
 *       them or waited for the thread that did. A caller that is interrupted while waiting keeps waiting and
 *       restores its interrupt flag on return.</li>
 *   <li>The withdrawal runs first, then the composition's stop. A failure of the first does not skip the
 *       second; the first failure is the one reported and a later one is attached to it as suppressed.
 *       A throwing action still releases every waiter, because the latch is released in a
 *       {@code finally}.</li>
 *   <li>The failure of the actions is returned to exactly one caller, the one that performed them; every
 *       waiting caller gets {@code null}. A {@link VirtualMachineError} is rethrown to the performing caller
 *       after the waiters are released.</li>
 *   <li>A stop requested before the composition is admitted leaves it unstarted: {@link #admit} then returns
 *       {@code false} and registers nothing. The registration and the stop each publish their own side before
 *       reading the other's (sequentially consistent atomics), so at least one of them sees the other: either
 *       the stop finds the admitted action and runs it, or the admission finds the stop and is refused.
 *       A stop that wins after the admission but before the composition starts is ordered against the start
 *       by the composition's own state, see {@code IdentityComposition#tryStart()}.</li>
 *   <li>No thread waits for another that waits for it: the performer waits only for the actions, which depend
 *       on no other caller of this class, and a waiter holds no lock.</li>
 * </ul>
 */
final class ServiceStop {

    private final Runnable withdraw;
    private final AtomicReference<Runnable> admitted = new AtomicReference<>();
    private final AtomicBoolean stopping = new AtomicBoolean();
    private final CountDownLatch stopped = new CountDownLatch(1);

    /**
     * Creates the stop of one service.
     *
     * @param withdraw the action that stops new work from entering, run first; it must not wait for this
     *                 object
     */
    ServiceStop(Runnable withdraw) {
        this.withdraw = withdraw;
    }

    /**
     * Registers the action that stops the composition, once.
     *
     * @param stopComposition the action that drains and terminates the composition; it must be safe to run
     *                        before the composition has started
     * @return {@code false} when a stop has already begun: the composition must then not be started
     */
    boolean admit(Runnable stopComposition) {
        admitted.set(stopComposition);
        return !stopping.get();
    }

    /**
     * Stops the service, or waits for the thread that is stopping it.
     *
     * @return the failure of the stop when this call performed it and it failed; {@code null} otherwise
     */
    Throwable stop() {
        if (!stopping.compareAndSet(false, true)) {
            awaitStopped();
            return null;
        }
        Throwable failure = null;
        try {
            failure = run(withdraw, failure);
            Runnable composition = admitted.get();
            if (composition != null) {
                failure = run(composition, failure);
            }
        } finally {
            stopped.countDown();
        }
        return failure;
    }

    private static Throwable run(Runnable action, Throwable earlier) {
        try {
            action.run();
            return earlier;
        } catch (VirtualMachineError fatal) {
            throw fatal;
        } catch (RuntimeException | Error e) {
            if (earlier == null) {
                return e;
            }
            earlier.addSuppressed(e);
            return earlier;
        }
    }

    private void awaitStopped() {
        boolean interrupted = false;
        while (true) {
            try {
                stopped.await();
                break;
            } catch (InterruptedException e) {
                interrupted = true;
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }
}
