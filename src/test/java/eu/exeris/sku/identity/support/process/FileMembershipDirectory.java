package eu.exeris.sku.identity.support.process;

import eu.exeris.sku.identity.auth.Membership;
import eu.exeris.sku.identity.auth.MembershipDirectory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** A membership table kept in a file of the host directory, so a test can seed it and read it back. */
public final class FileMembershipDirectory implements MembershipDirectory {

    static final String FILE = "memberships";

    @Override
    public List<Membership> memberships(UUID subjectId) {
        Map<UUID, String> byTenant = new LinkedHashMap<>();
        for (String line : HostFiles.lines(HostFiles.directory(), FILE)) {
            String[] parts = line.split("\\|");
            if (parts[0].equals(subjectId.toString())) {
                byTenant.put(UUID.fromString(parts[1]), parts[2]);
            }
        }
        List<Membership> result = new ArrayList<>();
        byTenant.forEach((tenant, role) -> result.add(new Membership(tenant, role)));
        return result;
    }

    @Override
    public void grant(UUID tenantId, UUID subjectId, String role) {
        RlsProbe.run("accept");
        HostFiles.append(FILE, subjectId + "|" + tenantId + "|" + role);
    }
}
