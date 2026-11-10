package eu.exeris.sku.identity.auth;

import eu.exeris.caps.serviceboundarycore.ServiceBoundaryCoreModule;
import eu.exeris.caps.serviceboundarycore.api.AdmissionContext;
import eu.exeris.caps.serviceboundarycore.api.AdmissionFilter;
import eu.exeris.caps.serviceboundarycore.api.AdmissionPhase;
import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRegistry;
import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRoute;
import eu.exeris.caps.serviceboundarycore.api.RouteMatch;
import eu.exeris.caps.sessionmanagement.api.SessionPrincipal;
import eu.exeris.kernel.spi.context.KernelProviders;
import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.http.RouteRequirement;
import eu.exeris.kernel.spi.security.PrincipalContext;
import eu.exeris.sku.identity.support.TestExchange;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("PrincipalBridge")
class PrincipalBridgeTest {

    private record Principal(UUID principalId, Optional<UUID> tenantId, Set<String> roles, Set<String> scopes)
            implements PrincipalContext {
    }

    private final UUID subject = UUID.randomUUID();
    private final UUID tenant = UUID.randomUUID();
    private final UUID session = UUID.randomUUID();
    private final AtomicReference<PrincipalContext> authenticated = new AtomicReference<>();
    private final AtomicReference<SessionPrincipal> seen = new AtomicReference<>();
    private final AtomicReference<PrincipalContext> seenKernelPrincipal = new AtomicReference<>();
    private final AtomicReference<Optional<String>> seenIsolationKey = new AtomicReference<>();
    private ApiSurfaceRegistry registry;

    @BeforeEach
    void setUp() {
        registry = ServiceBoundaryCoreModule.builder().strictRoutes(true).build().apiSurfaceRegistry();
        registry.registerFilter(new AdmissionFilter() {
            @Override
            public String name() {
                return "test-authenticator";
            }

            @Override
            public AdmissionPhase phase() {
                return AdmissionPhase.AUTHENTICATION;
            }

            @Override
            public boolean filter(HttpExchange exchange, RouteMatch routeMatch) {
                PrincipalContext principal = authenticated.get();
                if (principal != null) {
                    AdmissionContext.current().authenticate(principal, session);
                }
                return true;
            }
        });
        registry.registerRoute(ApiSurfaceRoute.builder()
                .method(HttpMethod.GET)
                .pathPattern("/whoami")
                .actionName("whoami")
                .requirements(List.of(RouteRequirement.permitAll()))
                .handler(PrincipalBridge.authenticated(exchange -> {
                    seen.set(SessionPrincipal.current());
                    seenKernelPrincipal.set(KernelProviders.principal());
                    seenIsolationKey.set(KernelProviders.storageContext().isolationKey());
                    exchange.respond(HttpStatus.OK);
                }))
                .build());
    }

    @Test
    @DisplayName("inside a bridged handler the session principal names the subject and the token's session")
    void principalIsBoundInsideTheHandler() {
        authenticated.set(new Principal(subject, Optional.of(tenant), Set.of("admin"), Set.of("invitations:write")));
        TestExchange exchange = TestExchange.of(HttpMethod.GET, "/whoami");

        registry.handle(exchange);

        assertThat(exchange.status()).isEqualTo(HttpStatus.OK);
        assertThat(seen.get().subjectId()).isEqualTo(subject);
        assertThat(seen.get().sessionId()).contains(session);
        assertThat(seenKernelPrincipal.get().tenantId()).contains(tenant);
        assertThat(seenKernelPrincipal.get().hasRole("admin")).isTrue();
        assertThat(seenKernelPrincipal.get().hasScope("invitations:write")).isTrue();
        assertThat(seenIsolationKey.get()).contains(tenant.toString());
    }

    @Test
    @DisplayName("a principal without a tenant leaves the isolation key empty")
    void tenantlessPrincipalHasNoIsolationKey() {
        authenticated.set(new Principal(subject, Optional.empty(), Set.of(), Set.of()));

        registry.handle(TestExchange.of(HttpMethod.GET, "/whoami"));

        assertThat(seenIsolationKey.get()).isEmpty();
    }

    @Test
    @DisplayName("outside a bridged handler there is no session principal")
    void principalIsAbsentOutsideTheHandler() {
        authenticated.set(new Principal(subject, Optional.of(tenant), Set.of(), Set.of()));
        registry.handle(TestExchange.of(HttpMethod.GET, "/whoami"));

        assertThatThrownBy(SessionPrincipal::current).hasMessageContaining("PrincipalContext not bound");
        assertThat(KernelProviders.PRINCIPAL_CONTEXT.isBound()).isFalse();
        assertThat(KernelProviders.STORAGE_CONTEXT.isBound()).isFalse();
    }

    @Test
    @DisplayName("a request with no principal gets 401 and the handler does not run")
    void unauthenticatedRequestIsRefused() {
        authenticated.set(null);
        TestExchange exchange = TestExchange.of(HttpMethod.GET, "/whoami");

        registry.handle(exchange);

        assertThat(exchange.status()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(seen.get()).isNull();
    }

    @Test
    @DisplayName("TenantScope binds the isolation key for the work and releases it afterwards")
    void tenantScopeBindsTheKey() {
        String inside = TenantScope.call(tenant, () -> KernelProviders.storageContext().isolationKey().orElse(""));

        assertThat(inside).isEqualTo(tenant.toString());
        assertThat(KernelProviders.STORAGE_CONTEXT.isBound()).isFalse();
    }
}
