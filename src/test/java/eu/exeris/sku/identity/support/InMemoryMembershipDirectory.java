package eu.exeris.sku.identity.support;

import eu.exeris.sku.identity.auth.Membership;
import eu.exeris.sku.identity.auth.MembershipDirectory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

/** A directory held in memory, for tests. */
public final class InMemoryMembershipDirectory implements MembershipDirectory {

    /** One call to {@code grant}. */
    public record Grant(UUID tenantId, UUID subjectId, String role) {
    }

    private final Map<UUID, Map<UUID, String>> bySubject = new ConcurrentHashMap<>();
    private final List<Grant> grants = new CopyOnWriteArrayList<>();
    private final AtomicBoolean failNextGrant = new AtomicBoolean();
    private final AtomicBoolean failNextAfterGrant = new AtomicBoolean();

    /** Makes the next grant throw before it records anything. */
    public void failNextGrant() {
        failNextGrant.set(true);
    }

    /** Makes the next grant record itself and then throw. */
    public void failNextAfterGrant() {
        failNextAfterGrant.set(true);
    }

    /** Every grant made, in order. */
    public List<Grant> grants() {
        return grants;
    }

    @Override
    public List<Membership> memberships(UUID subjectId) {
        List<Membership> result = new ArrayList<>();
        bySubject.getOrDefault(subjectId, Map.of()).forEach((tenant, role) -> result.add(new Membership(tenant, role)));
        return result;
    }

    @Override
    public void grant(UUID tenantId, UUID subjectId, String role) {
        if (failNextGrant.getAndSet(false)) {
            throw new IllegalStateException("the directory is unavailable");
        }
        bySubject.computeIfAbsent(subjectId, k -> new ConcurrentHashMap<>()).put(tenantId, role);
        grants.add(new Grant(tenantId, subjectId, role));
        if (failNextAfterGrant.getAndSet(false)) {
            throw new IllegalStateException("the directory failed after recording");
        }
    }
}
