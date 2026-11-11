package eu.exeris.sku.identity.support.process;

import eu.exeris.sku.identity.auth.Membership;
import eu.exeris.sku.identity.auth.MembershipDirectory;

import java.util.List;
import java.util.UUID;

/** A host directory whose store is down: every grant throws, with a message a launcher must not print. */
public final class FailingMembershipDirectory implements MembershipDirectory {

    /** The message of the failure; a test asserts it never reaches the output. */
    public static final String MESSAGE = "membership store down: host-internal-detail";

    @Override
    public List<Membership> memberships(UUID subjectId) {
        return List.of();
    }

    @Override
    public void grant(UUID tenantId, UUID subjectId, String role) {
        throw new IllegalStateException(MESSAGE);
    }
}
