package eu.exeris.sku.identity.auth;

import eu.exeris.kernel.spi.context.KernelProviders;
import eu.exeris.kernel.spi.security.StorageContext;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Binds the tenant the persistence layer isolates rows by, for work that runs outside an authenticated
 * request, such as accepting an invitation before the invitee has a token.
 *
 * <p>The tenant is validated state: it comes from a record this service has already matched, never from
 * an unchecked request field alone.
 */
public final class TenantScope {

    private TenantScope() {
    }

    /**
     * Runs the work with the persistence isolation key set to the tenant.
     *
     * @param tenantId the tenant whose rows the work may see
     * @param work     the work
     */
    public static void run(UUID tenantId, Runnable work) {
        bind(tenantId).run(work);
    }

    /**
     * Runs the work with the persistence isolation key set to the tenant and returns its result.
     *
     * @param tenantId the tenant whose rows the work may see
     * @param work     the work
     * @param <T>      the result type
     * @return what the work returned
     */
    public static <T> T call(UUID tenantId, Supplier<T> work) {
        return bind(tenantId).call(work::get);
    }

    /** The storage context for a tenant, or for no tenant when it is null. */
    static StorageContext storageContextOf(UUID tenantId) {
        return new TenantStorageContext(tenantId == null ? null : tenantId.toString());
    }

    /** Binds the isolation key for the tenant, or for no tenant when it is null. */
    static ScopedValue.Carrier bind(UUID tenantId) {
        return ScopedValue.where(KernelProviders.STORAGE_CONTEXT, storageContextOf(tenantId));
    }

    private record TenantStorageContext(String key) implements StorageContext {

        @Override
        public Optional<String> isolationKey() {
            return Optional.ofNullable(key);
        }

        @Override
        public IsolationStrategy strategy() {
            return IsolationStrategy.SHARED;
        }

        @Override
        public Optional<String> schemaName() {
            return Optional.empty();
        }

        @Override
        public Optional<String> dataSourceKey() {
            return Optional.empty();
        }

        @Override
        public Map<String, String> attributes() {
            return Map.of();
        }
    }
}
