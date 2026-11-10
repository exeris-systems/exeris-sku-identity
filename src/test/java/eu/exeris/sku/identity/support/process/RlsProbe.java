package eu.exeris.sku.identity.support.process;

import eu.exeris.kernel.spi.context.KernelProviders;
import eu.exeris.kernel.spi.persistence.QueryResult;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;

/**
 * Called from a host double while a request is being served: records which tenant the request is bound
 * to, and how many invitations of each of two named tenants the request's own unit can see. The counts
 * are read through the executor the launcher hands the host parts, so inside a unit they run on the
 * connection and in the transaction the request's own statements use. The query names both tenants
 * explicitly, so only row-level security keyed on the tenant the kernel publishes on that connection can
 * hide the rows of the other one.
 */
final class RlsProbe {

    static final String FILE = "probe";
    static final String TENANT_A = "IDENTITY_TEST_PROBE_TENANT_A";
    static final String TENANT_B = "IDENTITY_TEST_PROBE_TENANT_B";

    private static volatile TransactionalExecutor executor;

    private RlsProbe() {
    }

    /** Stores the executor the launcher hands a host part; every double hands over the same one. */
    static void join(TransactionalExecutor joining) {
        executor = joining;
    }

    /**
     * Appends {@code label|boundTenant|visibleOfA|visibleOfB}; an unreadable count is recorded as the
     * failure's class, and a probe run before any part was handed the executor as {@code error:not-joined}.
     */
    static void run(String label) {
        String bound = KernelProviders.STORAGE_CONTEXT.isBound()
                ? KernelProviders.STORAGE_CONTEXT.get().isolationKey().orElse("")
                : "unbound";
        HostFiles.append(FILE, label + "|" + bound + "|" + visible(System.getenv(TENANT_A)) + "|"
                + visible(System.getenv(TENANT_B)));
    }

    private static String visible(String tenant) {
        TransactionalExecutor joined = executor;
        if (joined == null) {
            return "error:not-joined";
        }
        try {
            Long count = joined.query(connection -> {
                try (var statement = connection.prepare(
                        "SELECT count(*) FROM invitations WHERE tenant_id = $1::uuid")) {
                    statement.bindString(0, tenant);
                    try (QueryResult rows = statement.executeQuery()) {
                        rows.next();
                        return rows.row().getLong(0);
                    }
                }
            });
            return String.valueOf(count);
        } catch (RuntimeException e) {
            return "error:" + e.getClass().getSimpleName();
        }
    }
}
