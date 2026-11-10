package eu.exeris.sku.identity.support.process;

import eu.exeris.kernel.spi.context.KernelProviders;
import eu.exeris.kernel.spi.persistence.QueryResult;

/**
 * Called from a host double while a request is being served: records which tenant the kernel's executor is
 * bound to, and how many invitations of each of two named tenants that executor can see. The query names
 * both tenants explicitly, so only row-level security keyed on the tenant the kernel publishes can hide the
 * rows of the other one.
 */
final class RlsProbe {

    static final String FILE = "probe";
    static final String TENANT_A = "IDENTITY_TEST_PROBE_TENANT_A";
    static final String TENANT_B = "IDENTITY_TEST_PROBE_TENANT_B";

    private RlsProbe() {
    }

    /** Appends {@code label|boundTenant|visibleOfA|visibleOfB}; an unreadable count is recorded as the failure's class. */
    static void run(String label) {
        String bound = KernelProviders.STORAGE_CONTEXT.isBound()
                ? KernelProviders.STORAGE_CONTEXT.get().isolationKey().orElse("")
                : "unbound";
        HostFiles.append(FILE, label + "|" + bound + "|" + visible(System.getenv(TENANT_A)) + "|"
                + visible(System.getenv(TENANT_B)));
    }

    private static String visible(String tenant) {
        try {
            Long count = KernelProviders.transactionalExecutor().query(connection -> {
                var statement = connection.prepare("SELECT count(*) FROM invitations WHERE tenant_id = $1::uuid");
                statement.bindString(0, tenant);
                try (QueryResult rows = statement.executeQuery()) {
                    rows.next();
                    return rows.row().getLong(0);
                }
            });
            return String.valueOf(count);
        } catch (RuntimeException e) {
            return "error:" + e.getClass().getSimpleName();
        }
    }
}
