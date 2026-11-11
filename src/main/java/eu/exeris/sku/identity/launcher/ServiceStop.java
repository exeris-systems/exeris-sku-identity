package eu.exeris.sku.identity.launcher;

import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The one place a served composition is stopped. The thread that finishes serving and the shutdown hook
 * both ask; one of them performs the stop and the other waits for it.
 *
 * <h2>State</h2>
 *
 * <p>One {@link AtomicReference} holds the whole state, and every change is a compare-and-set on it:
 * <pre>
 *   OPEN(no action) --admit--> OPEN(action) --stop--> STOPPING(performer) --done--> STOPPED
 *   OPEN(no action) --stop---------------------------^
 * </pre>
 * {@code admit} is a compare-and-set from {@code OPEN(no action)} to {@code OPEN(action)} and succeeds only
 * there; {@code stop} is a compare-and-set from {@code OPEN(x)}, whatever {@code x} is, to
 * {@code STOPPING(current thread)} and takes {@code x} from the state it replaced. The performer stores
 * {@code STOPPED} and then releases the latch.
 *
 * <p>Invariants:
 * <ul>
 *   <li>Exactly one of: the registered action ran, or {@link #admit} returned {@code false}. The two
 *       compare-and-sets act on one variable, so they are totally ordered. If the admission's came first, the
 *       state the stop replaces holds the action, and the stop (the only one that can leave {@code OPEN})
 *       runs it; a stop that read the state before the admission fails its compare-and-set and reads again.
 *       If the stop's came first, the state is no longer {@code OPEN} and the admission fails without
 *       storing anything the performer could reach. There is no third case, and no window in which the
 *       action is stored and not run, or run and refused.</li>
 *   <li>The stop actions run at most once, however many threads call {@link #stop()}: only the caller whose
 *       compare-and-set leaves {@code OPEN} runs them.</li>
 *   <li>Every call of {@link #stop()} from a thread other than the performer returns only after the actions
 *       have completed. The wait has no time limit and is not abandoned on an interrupt: a caller that is
 *       interrupted while waiting keeps waiting and restores its interrupt flag on return, so an action that
 *       never returns holds its waiters for as long as it runs.</li>
 *   <li>A call from the performing thread itself, that is from inside an action, returns {@code null}
 *       immediately: the stop is in progress on this very thread, and waiting for its completion would wait
 *       for a thread that is waiting. The performer is recorded in the state it creates, so the check cannot
 *       see a performer that is not yet set. An action must still not hand the call to another thread and
 *       wait for that thread.</li>
 *   <li>The withdrawal runs first, then the composition's stop. A failure of the first does not skip the
 *       second; the first failure is the one reported and a later one is attached to it as suppressed,
 *       except that a {@link VirtualMachineError} takes precedence over any other failure.
 *       A throwing action still releases every waiter, because the latch is released in a
 *       {@code finally}.</li>
 *   <li>The failure of the actions is returned to exactly one caller, the one that performed them; every
 *       other caller gets {@code null}. A {@link VirtualMachineError} is rethrown to the performing caller
 *       after both actions have run and the waiters are released.</li>
 *   <li>A stop requested before the composition is admitted leaves it unstarted: {@link #admit} then returns
 *       {@code false} and registers nothing. A stop that wins after the admission but before the composition
 *       starts is ordered against the start by the composition's own state, see
 *       {@code IdentityComposition#tryStart()}.</li>
 *   <li>No thread waits for another that waits for it: the performer waits only for the actions, which depend
 *       on no other caller of this class, and a waiter holds no lock.</li>
 * </ul>
 */
final class ServiceStop {

    private sealed interface State permits Open, Stopping, Stopped {
    }

    /** No stop has begun; {@code action} is {@code null} until the composition is admitted. */
    private record Open(Runnable action) implements State {
    }

    /** A stop is being performed by {@code performer}. */
    private record Stopping(Thread performer) implements State {
    }

    /** The stop has completed. */
    private record Stopped() implements State {
    }

    private static final Open NOTHING_ADMITTED = new Open(null);

    private final Runnable withdraw;
    private final AtomicReference<State> state = new AtomicReference<>(NOTHING_ADMITTED);
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
     *                        before the composition has started; never {@code null}
     * @return {@code false} when a stop has already begun: nothing is registered and the composition must
     *         not be started
     * @throws NullPointerException  when the action is {@code null}; nothing is registered, so a real action
     *                               can still be admitted
     * @throws IllegalStateException when an action was already admitted
     */
    boolean admit(Runnable stopComposition) {
        Objects.requireNonNull(stopComposition, "stopComposition");
        Open admitted = new Open(stopComposition);
        while (true) {
            State current = state.get();
            if (!(current instanceof Open open)) {
                return false;
            }
            if (open.action() != null) {
                throw new IllegalStateException("an action has already been admitted");
            }
            if (state.compareAndSet(current, admitted)) {
                return true;
            }
        }
    }

    /**
     * Stops the service, or waits for the thread that is stopping it.
     *
     * @return the failure of the stop when this call performed it and it failed; {@code null} otherwise,
     *         including a call made from inside the stop actions on the performing thread
     */
    Throwable stop() {
        Thread caller = Thread.currentThread();
        while (true) {
            State current = state.get();
            switch (current) {
                case Open open -> {
                    if (state.compareAndSet(current, new Stopping(caller))) {
                        return perform(open.action());
                    }
                }
                case Stopping stopping -> {
                    if (stopping.performer() != caller) {
                        awaitStopped();
                    }
                    return null;
                }
                case Stopped done -> {
                    return null;
                }
            }
        }
    }

    private Throwable perform(Runnable composition) {
        Throwable failure = null;
        try {
            failure = run(withdraw, failure);
            if (composition != null) {
                failure = run(composition, failure);
            }
        } finally {
            state.set(new Stopped());
            stopped.countDown();
        }
        if (failure instanceof VirtualMachineError fatal) {
            throw fatal;
        }
        return failure;
    }

    /**
     * Runs one action and folds its failure into {@code earlier}: the first failure is kept and a later one
     * is suppressed onto it, except that a {@link VirtualMachineError} takes the first place and carries
     * the failure it replaces as suppressed. Nothing is rethrown here, so the action that follows always runs.
     */
    private static Throwable run(Runnable action, Throwable earlier) {
        try {
            action.run();
            return earlier;
        } catch (RuntimeException | Error e) {
            if (earlier == null || e == earlier) {
                return e;
            }
            if (e instanceof VirtualMachineError && !(earlier instanceof VirtualMachineError)) {
                e.addSuppressed(earlier);
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
