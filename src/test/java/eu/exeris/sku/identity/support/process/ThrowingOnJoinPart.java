package eu.exeris.sku.identity.support.process;

import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import eu.exeris.sku.identity.auth.JoinsServiceTransactions;
import eu.exeris.sku.identity.auth.Membership;
import eu.exeris.sku.identity.auth.MembershipDirectory;

import java.util.List;
import java.util.UUID;

/**
 * A host directory that throws an {@link Error} instead of an exception at the point the launcher hands it
 * the transactional executor. Which error is chosen by the process environment, and its message carries
 * a marker from the environment so that a test can make it unguessable and assert it never reaches the
 * output. The errors are thrown instances: nothing is really exhausted.
 */
public final class ThrowingOnJoinPart implements MembershipDirectory, JoinsServiceTransactions {

    /** Written to the standard error just before the error is thrown, so a test can time what follows. */
    public static final String THROWING_LINE = "host part is about to throw";
    /** The variable holding the text of the error's message. */
    public static final String MARKER_VARIABLE = "IDENTITY_TEST_ERROR_MARKER";
    /** The variable choosing the error: {@value #NO_CLASS_DEF}, {@value #OUT_OF_MEMORY} or {@value #PARK}. */
    public static final String KIND_VARIABLE = "IDENTITY_TEST_ERROR_KIND";
    /** A class that cannot be loaded, an {@link Error} that is not a {@link VirtualMachineError}. */
    public static final String NO_CLASS_DEF = "no-class-def";
    /** Not an error: the part parks until the process ends, so a test can stop a service that is still starting. */
    public static final String PARK = "park";
    /** Written to the standard error when the part parks. */
    public static final String PARKED_LINE = "host part is parked";
    /** A fatal VM error. */
    public static final String OUT_OF_MEMORY = "out-of-memory";

    @Override
    public void joinTransactionsOf(TransactionalExecutor executor) {
        String message = "host part error: " + System.getenv(MARKER_VARIABLE);
        String kind = System.getenv(KIND_VARIABLE);
        if (PARK.equals(kind)) {
            System.err.println(PARKED_LINE);
            try {
                Thread.sleep(Long.MAX_VALUE);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return;
        }
        System.err.println(THROWING_LINE);
        switch (kind) {
            case NO_CLASS_DEF -> throw new NoClassDefFoundError(message);
            case OUT_OF_MEMORY -> throw new OutOfMemoryError(message);
            default -> throw new IllegalStateException("no error kind chosen");
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
