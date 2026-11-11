package eu.exeris.sku.identity.support.process;

import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import eu.exeris.sku.identity.auth.JoinsServiceTransactions;
import eu.exeris.sku.identity.auth.Membership;
import eu.exeris.sku.identity.auth.MembershipDirectory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.util.List;
import java.util.UUID;

/**
 * A file-backed directory whose {@code grant} parks until the test creates the {@value #RELEASE} file in the
 * host directory. On entering it records the subject in the {@value #PARKED} file, so the test knows the
 * launched process is inside its transaction with the account written and not yet committed.
 */
public final class ParkingMembershipDirectory implements MembershipDirectory, JoinsServiceTransactions {

    /** Appended to when a grant has been entered. */
    public static final String PARKED = "parked";
    /** The file whose existence lets a parked grant proceed. */
    public static final String RELEASE = "release";

    private static final long LIMIT_NANOS = 180_000_000_000L;

    private final FileMembershipDirectory delegate = new FileMembershipDirectory();

    @Override
    public void joinTransactionsOf(TransactionalExecutor executor) {
        delegate.joinTransactionsOf(executor);
    }

    @Override
    public List<Membership> memberships(UUID subjectId) {
        return delegate.memberships(subjectId);
    }

    @Override
    public void grant(UUID tenantId, UUID subjectId, String role) {
        HostFiles.append(PARKED, subjectId.toString());
        long deadline = System.nanoTime() + LIMIT_NANOS;
        while (!Files.exists(HostFiles.directory().resolve(RELEASE))) {
            if (System.nanoTime() > deadline) {
                throw new IllegalStateException("never released");
            }
            try {
                Thread.sleep(20);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new UncheckedIOException(new IOException("interrupted"));
            }
        }
        delegate.grant(tenantId, subjectId, role);
    }
}
