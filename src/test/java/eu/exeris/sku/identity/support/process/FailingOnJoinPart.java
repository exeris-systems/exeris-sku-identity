package eu.exeris.sku.identity.support.process;

import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import eu.exeris.sku.identity.auth.JoinsServiceTransactions;
import eu.exeris.sku.identity.auth.Membership;
import eu.exeris.sku.identity.auth.MembershipDirectory;

import java.util.List;
import java.util.UUID;

/**
 * A host directory that fails at the point the launcher hands it the transactional executor, which is
 * after the kernel is up and before the service accepts anything. The message is taken from the process
 * environment so that a test can make it unguessable and assert it never reaches the output.
 */
public final class FailingOnJoinPart implements MembershipDirectory, JoinsServiceTransactions {

    /** The variable holding the text of the failure's message. */
    public static final String MARKER_VARIABLE = "IDENTITY_TEST_FAILURE_MARKER";

    @Override
    public void joinTransactionsOf(TransactionalExecutor executor) {
        throw new IllegalStateException("host part failed: " + System.getenv(MARKER_VARIABLE));
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
