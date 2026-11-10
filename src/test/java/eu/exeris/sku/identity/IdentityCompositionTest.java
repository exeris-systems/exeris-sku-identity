package eu.exeris.sku.identity;

import eu.exeris.caps.serviceboundarycore.ServiceBoundaryCoreModule;
import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRoute;
import eu.exeris.caps.sessionmanagement.api.SessionPrincipal;
import eu.exeris.kernel.community.security.Argon2idPasswordEncoder;
import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.http.RouteRequirement;
import eu.exeris.kernel.spi.security.credentials.PasswordEncoderConfig;
import eu.exeris.sku.identity.auth.PrincipalBridge;
import eu.exeris.sku.identity.config.IdentityConfig;
import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.JdbcTransactionalExecutor;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.RecordingNotificationDispatcher;
import eu.exeris.sku.identity.support.TestConfig;
import eu.exeris.sku.identity.support.TestExchange;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("IdentityComposition")
class IdentityCompositionTest {

    private PostgresSupport.Database database;

    private final InMemoryMembershipDirectory directory = new InMemoryMembershipDirectory();
    private final AtomicReference<SessionPrincipal> seen = new AtomicReference<>();
    private IdentityComposition composition;

    @BeforeEach
    void migrate() throws Exception {
        database = PostgresSupport.newDatabase();
    }

    @AfterEach
    void stop() {
        if (composition != null) {
            composition.stop(Duration.ofSeconds(1));
        }
    }

    private IdentityComposition.Builder builder() {
        return builder(database);
    }

    private static IdentityComposition.Builder builder(PostgresSupport.Database target) {
        IdentityConfig config = TestConfig.load();
        return IdentityComposition.builder()
                .config(config)
                .transactionalExecutor(new JdbcTransactionalExecutor(target))
                .passwordEncoder(new Argon2idPasswordEncoder(new PasswordEncoderConfig(8_192, 1, 1, 32)))
                .notificationDispatcher(new RecordingNotificationDispatcher())
                .membershipDirectory(new InMemoryMembershipDirectory());
    }

    private RouteContributor probe() {
        return new RouteContributor() {
            @Override
            public List<ApiSurfaceRoute> routes(IdentityServices services) {
                return List.of(ApiSurfaceRoute.builder()
                        .method(HttpMethod.GET)
                        .pathPattern("/probe")
                        .actionName("probe")
                        .requirements(List.of(RouteRequirement.authenticated()))
                        .handler(PrincipalBridge.authenticated(exchange -> {
                            seen.set(SessionPrincipal.current());
                            exchange.respond(HttpStatus.OK);
                        }))
                        .build());
            }
        };
    }

    private static HttpHeader bearer(String token) {
        return new HttpHeader("Authorization", "Bearer " + token);
    }

    @Test
    @DisplayName("a service boundary that is not strict is refused")
    void nonStrictBoundaryIsRefused() {
        IdentityComposition.Builder builder = builder()
                .serviceBoundary(ServiceBoundaryCoreModule.builder().build());

        assertThatThrownBy(builder::build)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("strict");
    }

    @Test
    @DisplayName("a missing required part is named")
    void missingPartIsNamed() {
        assertThatThrownBy(() -> IdentityComposition.builder().config(TestConfig.load()).build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("transactionalExecutor");
    }

    @Test
    @DisplayName("a host-supplied strict boundary is used, and start freezes the registry")
    void startFreezesTheRegistry() throws Exception {
        ServiceBoundaryCoreModule host = ServiceBoundaryCoreModule.builder().strictRoutes(true).build();
        composition = builder().serviceBoundary(host).routes(probe()).build();
        ApiSurfaceRoute late = ApiSurfaceRoute.builder()
                .method(HttpMethod.GET)
                .pathPattern("/late")
                .actionName("late")
                .requirements(List.of(RouteRequirement.permitAll()))
                .handler(exchange -> exchange.respond(HttpStatus.OK))
                .build();

        assertThat(composition.apiSurfaceRegistry()).isSameAs(host.apiSurfaceRegistry());
        composition.apiSurfaceRegistry().registerRoute(late);
        composition.apiSurfaceRegistry().unregisterRoute(late);

        composition.start();

        assertThatThrownBy(() -> composition.apiSurfaceRegistry().registerRoute(late))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(composition::start).isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("the key set is served without a token, and the other routes need one")
    void keySetIsPublic() throws Exception {
        composition = builder().routes(probe()).build();
        composition.start();

        TestExchange keys = TestExchange.of(HttpMethod.GET, "/.well-known/jwks.json");
        composition.apiSurfaceRegistry().handle(keys);
        TestExchange anonymousProbe = TestExchange.of(HttpMethod.GET, "/probe");
        composition.apiSurfaceRegistry().handle(anonymousProbe);

        assertThat(keys.status()).isEqualTo(HttpStatus.OK);
        assertThat(anonymousProbe.status()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(composition.jwksPublisher().getJwksJson()).contains("\"keys\"");
    }

    @Test
    @DisplayName("a token the service issued is accepted, and the handler sees its subject and session")
    void issuedTokenAuthenticates() throws Exception {
        composition = builder().routes(probe()).membershipDirectory(directory).build();
        composition.start();
        UUID subject = UUID.randomUUID();
        UUID session = UUID.randomUUID();
        UUID tenant = UUID.randomUUID();
        directory.grant(tenant, subject, "admin");
        String token = composition.services().sessionAccessTokens().issueAccessToken(subject, session).token();

        TestExchange exchange = TestExchange.of(HttpMethod.GET, "/probe", bearer(token));
        composition.apiSurfaceRegistry().handle(exchange);

        assertThat(exchange.status()).isEqualTo(HttpStatus.OK);
        assertThat(seen.get().subjectId()).isEqualTo(subject);
        assertThat(seen.get().sessionId()).contains(session);
    }

    @Test
    @DisplayName("a token signed by other keys is refused")
    void foreignTokenIsRefused() throws Exception {
        IdentityComposition other = builder(PostgresSupport.newDatabase()).build();
        other.start();
        composition = builder().routes(probe()).build();
        composition.start();
        try {
            String foreign = other.services().sessionAccessTokens()
                    .issueAccessToken(UUID.randomUUID(), UUID.randomUUID()).token();

            TestExchange exchange = TestExchange.of(HttpMethod.GET, "/probe", bearer(foreign));
            composition.apiSurfaceRegistry().handle(exchange);

            assertThat(exchange.status()).isEqualTo(HttpStatus.UNAUTHORIZED);
        } finally {
            other.stop(Duration.ofSeconds(1));
        }
    }

    @Test
    @DisplayName("the tenant filter is the service boundary's, for a host to register")
    void tenantFilterIsProvided() throws Exception {
        composition = builder().build();

        assertThat(composition.tenantMembershipFilter("tenantId").bypassingRoles(Set.of("platform-admin")).name())
                .isEqualTo("tenant-membership");
        assertThat(composition.credentialProvisioning()).isNotNull();
        assertThat(composition.jwtAdmissionPolicy()).isNotNull();
        assertThat(composition.jwtBinding()).isNotNull();
    }
}
