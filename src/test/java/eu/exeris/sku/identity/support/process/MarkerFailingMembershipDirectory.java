package eu.exeris.sku.identity.support.process;

import eu.exeris.sku.identity.auth.Membership;
import eu.exeris.sku.identity.auth.MembershipDirectory;

import java.sql.SQLException;
import java.util.List;
import java.util.UUID;

/**
 * A host directory that looks nobody up: every lookup throws an exception whose message, and whose root
 * cause's message, carry the text of {@value #MARKER_VARIABLE}, as a driver's message can carry a
 * connection URL. A grant succeeds and records nothing.
 */
public final class MarkerFailingMembershipDirectory implements MembershipDirectory {

    /** The variable holding the text the failure's messages carry. */
    public static final String MARKER_VARIABLE = "IDENTITY_TEST_LOOKUP_MARKER";

    @Override
    public List<Membership> memberships(UUID subjectId) {
        String marker = System.getenv(MARKER_VARIABLE);
        throw new IllegalStateException("membership store unreachable: " + marker,
                new SQLException("jdbc:postgresql://u:" + marker + "@store.example.test/db password=" + marker));
    }

    @Override
    public void grant(UUID tenantId, UUID subjectId, String role) {
        // nothing to record
    }
}
