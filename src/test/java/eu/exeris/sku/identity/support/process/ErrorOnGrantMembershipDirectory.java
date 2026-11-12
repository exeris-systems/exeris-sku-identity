package eu.exeris.sku.identity.support.process;

import eu.exeris.sku.identity.auth.Membership;
import eu.exeris.sku.identity.auth.MembershipDirectory;

import java.util.List;
import java.util.UUID;

/**
 * A host directory whose {@code grant} throws an {@link Error} from inside the transaction that has already
 * written the account. The error is chosen by {@value #KIND_VARIABLE} and carries the text of
 * {@value #MARKER_VARIABLE} as its message, so that a test can make the message unguessable and assert it never
 * reaches the output. The errors are thrown instances; nothing is exhausted.
 */
public final class ErrorOnGrantMembershipDirectory implements MembershipDirectory {

    /** The variable holding the text of the error's message. */
    public static final String MARKER_VARIABLE = "IDENTITY_TEST_GRANT_ERROR_MARKER";
    /** The variable choosing the error: {@value #NO_CLASS_DEF} or {@value #OUT_OF_MEMORY}. */
    public static final String KIND_VARIABLE = "IDENTITY_TEST_GRANT_ERROR_KIND";
    /** An {@link Error} that is not a {@link VirtualMachineError}. */
    public static final String NO_CLASS_DEF = "no-class-def";
    /** A fatal VM error. */
    public static final String OUT_OF_MEMORY = "out-of-memory";

    @Override
    public List<Membership> memberships(UUID subjectId) {
        return List.of();
    }

    @Override
    public void grant(UUID tenantId, UUID subjectId, String role) {
        String message = "grant error: " + System.getenv(MARKER_VARIABLE);
        switch (String.valueOf(System.getenv(KIND_VARIABLE))) {
            case NO_CLASS_DEF -> throw new NoClassDefFoundError(message);
            case OUT_OF_MEMORY -> throw new OutOfMemoryError(message);
            default -> throw new IllegalStateException("no error kind chosen");
        }
    }
}
