package eu.exeris.sku.identity.auth;

import eu.exeris.caps.serviceboundarycore.api.RequestContext;
import eu.exeris.caps.sessionmanagement.api.SessionBoundPrincipal;
import eu.exeris.kernel.spi.context.KernelProviders;
import eu.exeris.kernel.spi.http.HttpHandler;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.security.PrincipalContext;

import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Makes the principal the admission filters authenticated visible to code that reads the kernel's
 * principal slot, such as the session store.
 *
 * <p>The admission chain keeps the authenticated principal in the service boundary's request context and
 * never binds {@link KernelProviders#PRINCIPAL_CONTEXT}. A handler wrapped by {@link #authenticated}
 * runs with that slot bound to the same principal, extended with the session the token names, and with the
 * persistence isolation key set to the principal's tenant. A request with no principal gets 401 and the
 * handler does not run.
 */
public final class PrincipalBridge {

    private PrincipalBridge() {
    }

    /**
     * Wraps a handler of an authenticated route.
     *
     * @param delegate the handler
     * @return a handler that binds the principal for the delegate
     */
    public static HttpHandler authenticated(HttpHandler delegate) {
        Objects.requireNonNull(delegate, "delegate must not be null");
        return exchange -> {
            Optional<PrincipalContext> principal = RequestContext.isBound()
                    ? RequestContext.current().principal()
                    : Optional.empty();
            if (principal.isEmpty()) {
                exchange.respond(HttpStatus.UNAUTHORIZED);
                return;
            }
            UUID sessionId = RequestContext.current().sessionId().orElse(null);
            run(principal.get(), sessionId, () -> delegate.handle(exchange));
        };
    }

    /**
     * Runs work with the kernel's principal slot bound to the principal and session.
     *
     * @param principal the authenticated principal
     * @param sessionId the session the credential belongs to; null when it names none
     * @param work      the work
     */
    public static void run(PrincipalContext principal, UUID sessionId, Runnable work) {
        Objects.requireNonNull(principal, "principal must not be null");
        UUID tenant = principal.tenantId().orElse(null);
        ScopedValue.where(KernelProviders.PRINCIPAL_CONTEXT, new Bridged(principal, sessionId))
                .where(KernelProviders.STORAGE_CONTEXT, TenantScope.storageContextOf(tenant))
                .run(work);
    }

    /** A principal that also names its session; every other answer is the wrapped principal's. */
    private record Bridged(PrincipalContext principal, UUID sessionId) implements SessionBoundPrincipal {

        @Override
        public UUID principalId() {
            return principal.principalId();
        }

        @Override
        public Optional<UUID> tenantId() {
            return principal.tenantId();
        }

        @Override
        public Set<String> roles() {
            return principal.roles();
        }

        @Override
        public Set<String> scopes() {
            return principal.scopes();
        }

        @Override
        public long roleMask() {
            return principal.roleMask();
        }

        @Override
        public boolean hasRole(String role) {
            return principal.hasRole(role);
        }

        @Override
        public boolean hasScope(String scope) {
            return principal.hasScope(scope);
        }

        @Override
        public String toString() {
            return "BridgedPrincipal[subject=" + principal.principalId() + ", session=" + sessionId + "]";
        }
    }
}
