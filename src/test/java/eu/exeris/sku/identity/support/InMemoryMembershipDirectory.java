package eu.exeris.sku.identity.support;

import eu.exeris.sku.identity.auth.Membership;
import eu.exeris.sku.identity.auth.MembershipDirectory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** A directory held in memory, for tests. */
public final class InMemoryMembershipDirectory implements MembershipDirectory {

    private final Map<UUID, Map<UUID, String>> bySubject = new ConcurrentHashMap<>();

    @Override
    public List<Membership> memberships(UUID subjectId) {
        List<Membership> result = new ArrayList<>();
        bySubject.getOrDefault(subjectId, Map.of()).forEach((tenant, role) -> result.add(new Membership(tenant, role)));
        return result;
    }

    @Override
    public void grant(UUID tenantId, UUID subjectId, String role) {
        bySubject.computeIfAbsent(subjectId, k -> new ConcurrentHashMap<>()).put(tenantId, role);
    }
}
