package eu.exeris.sku.identity.launcher;

import eu.exeris.kernel.spi.http.HttpKernelProviders;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import eu.exeris.sku.identity.auth.JoinsServiceTransactions;
import eu.exeris.sku.identity.auth.Membership;
import eu.exeris.sku.identity.auth.MembershipDirectory;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * A host part for the interrupt-timing tests. When the launcher hands it the transactional executor it either
 * does nothing ({@value #START}) or arranges that the serving thread is interrupted at the moment it asks to
 * hand the composition to the listener ({@value #SERVE}): a helper thread holds the monitor of the launcher's
 * switchable handler, which {@code serve} needs, waits for the serving thread to block on it, interrupts it,
 * and lets go.
 */
public final class InterruptingPart implements MembershipDirectory, JoinsServiceTransactions {

    /** The variable naming the mode. */
    public static final String MODE_VARIABLE = "IDENTITY_TEST_INTERRUPT_MODE";
    /** No arrangement; the test interrupts from outside. */
    public static final String START = "start";
    /** Interrupt while the serving thread is about to hand the composition to the listener. */
    public static final String SERVE = "serve";
    /** Written to the standard error when the helper has interrupted the serving thread. */
    public static final String INTERRUPTED_LINE = "INTERRUPTED_AT_SERVE";

    @Override
    public void joinTransactionsOf(TransactionalExecutor executor) {
        if (!SERVE.equals(System.getenv(MODE_VARIABLE))) {
            return;
        }
        Thread server = Thread.currentThread();
        Object handler = HttpKernelProviders.HTTP_SERVER_HANDLER.get();
        CountDownLatch holding = new CountDownLatch(1);
        Thread holder = new Thread(() -> {
            synchronized (handler) {
                holding.countDown();
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
                while (server.getState() != Thread.State.BLOCKED && System.nanoTime() < deadline) {
                    Thread.onSpinWait();
                }
                server.interrupt();
                System.err.println(INTERRUPTED_LINE);
            }
        }, "monitor-holder");
        holder.setDaemon(true);
        holder.start();
        try {
            holding.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    @Override
    public List<Membership> memberships(UUID subjectId) {
        return List.of();
    }

    @Override
    public void grant(UUID tenantId, UUID subjectId, String role) {
        throw new IllegalStateException("unreachable");
    }
}
