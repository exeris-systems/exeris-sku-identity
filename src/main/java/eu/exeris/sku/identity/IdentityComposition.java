package eu.exeris.sku.identity;

import eu.exeris.caps.audittrail.AuditTrailModule;
import eu.exeris.caps.audittrail.api.AuditLogSink;
import eu.exeris.caps.credentialstore.CredentialStoreModule;
import eu.exeris.caps.credentialstore.api.CredentialProvisioning;
import eu.exeris.caps.federatedlogin.FederatedLoginModule;
import eu.exeris.caps.i18n.I18nModule;
import eu.exeris.caps.invitations.InvitationsModule;
import eu.exeris.caps.jwt.JwtValidationModule;
import eu.exeris.caps.jwt.api.JwtAdmissionPolicies;
import eu.exeris.caps.jwt.api.JwtAdmissionPolicy;
import eu.exeris.caps.jwt.api.JwtServiceBoundaryBinding;
import eu.exeris.caps.mfatotp.MfaTotpModule;
import eu.exeris.caps.ratelimit.RateLimitModule;
import eu.exeris.caps.ratelimit.api.PeerAddressSource;
import eu.exeris.caps.ratelimit.api.RateLimitFilterSettings;
import eu.exeris.caps.ratelimit.api.RateLimitServiceBoundaryBinding;
import eu.exeris.caps.serviceboundarycore.ServiceBoundaryCoreModule;
import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRegistry;
import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRoute;
import eu.exeris.caps.serviceboundarycore.api.RequestFilterChain;
import eu.exeris.caps.serviceboundarycore.api.TenantMembershipFilter;
import eu.exeris.caps.sessionmanagement.SessionManagementModule;
import eu.exeris.caps.sessionmanagement.api.SessionPolicy;
import eu.exeris.caps.tokenissuer.TokenIssuerModule;
import eu.exeris.caps.tokenissuer.api.JwksPublisher;
import eu.exeris.caps.tokenissuer.spi.ApiSurfaceRegistryRegistrar;
import eu.exeris.kernel.spi.http.HttpHandler;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import eu.exeris.kernel.spi.scheduling.JobScheduler;
import eu.exeris.kernel.spi.security.credentials.KernelPasswordEncoder;
import eu.exeris.sdk.composition.lifecycle.CapabilityLifecycleHooks;
import eu.exeris.sku.identity.auth.AdaptiveArgon2Rehash;
import eu.exeris.sku.identity.auth.DirectoryInvitationAdministrators;
import eu.exeris.sku.identity.auth.InvitationDelivery;
import eu.exeris.sku.identity.auth.MembershipDirectory;
import eu.exeris.sku.identity.config.IdentityConfig;
import eu.exeris.sku.identity.persistence.JoiningTransactionalExecutor;
import eu.exeris.sku.identity.wiring.CommitOrderedAuditRecorder;
import eu.exeris.sku.identity.wiring.DeferredJwtPolicy;
import eu.exeris.sku.identity.wiring.PeerAddresses;
import eu.exeris.sku.identity.wiring.SessionRevocationAdapter;
import eu.exeris.sku.identity.wiring.SessionTokenIssuerAdapter;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * The identity service as a library: the twelve capabilities wired together over a host's persistence,
 * password hashing, notification and membership services, on one strict route registry.
 *
 * <p>{@link Builder#build()} composes the capabilities and registers every route from the
 * {@link RouteContributor}s. {@link #start()} initialises every capability and makes it ready; the
 * service boundary becomes ready last, which freezes the registry, so a host adds its own routes to
 * {@link #apiSurfaceRegistry()} between {@code build} and {@code start}. {@link #stop()} drains and
 * terminates in the reverse order.
 *
 * <p>The schema of the capabilities is applied beforehand, with
 * {@link eu.exeris.sku.identity.persistence.IdentityMigrations}.
 */
public final class IdentityComposition {

    /** The public key-set route the token issuer registers once it is ready. */
    static final String JWKS_ROUTE = "GET /.well-known/jwks.json";

    private final ServiceBoundaryCoreModule serviceBoundary;
    private final List<CapabilityLifecycleHooks> readyOrder;
    private final JwtAdmissionPolicy jwtPolicy;
    private final JwtServiceBoundaryBinding jwtBinding;
    private final CredentialProvisioning credentialProvisioning;
    private final IdentityServices services;
    private final JoiningTransactionalExecutor transactions;
    private State state = State.BUILT;

    private enum State { BUILT, STARTED, STOPPED }

    private IdentityComposition(ServiceBoundaryCoreModule serviceBoundary, List<CapabilityLifecycleHooks> readyOrder,
                                JwtAdmissionPolicy jwtPolicy, JwtServiceBoundaryBinding jwtBinding,
                                IdentityServices services) {
        this.serviceBoundary = serviceBoundary;
        this.readyOrder = readyOrder;
        this.jwtPolicy = jwtPolicy;
        this.jwtBinding = jwtBinding;
        this.credentialProvisioning = services.credentialProvisioning();
        this.services = services;
        this.transactions = services.transactions();
    }

    /**
     * Starts a composition.
     *
     * @return a builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Initialises every capability, then makes each ready: the token issuer first, so that the verifier is
     * built over a key set that already holds a signing key, and the service boundary last, which freezes
     * the route registry. A failure terminates what had been initialised and is rethrown.
     *
     * @throws Exception the failure of the capability that did not start
     */
    public synchronized void start() throws Exception {
        if (state != State.BUILT) {
            throw new IllegalStateException("the composition has been started");
        }
        state = State.STARTED;
        int initialised = 0;
        try {
            for (CapabilityLifecycleHooks module : readyOrder) {
                module.initialize();
                initialised++;
            }
            for (CapabilityLifecycleHooks module : readyOrder) {
                module.ready();
            }
        } catch (Exception | Error failure) {
            terminateFirst(initialised);
            state = State.STOPPED;
            throw failure;
        }
    }

    /**
     * Drains every capability, then terminates them, in the reverse order of start. Calling it when not
     * started does nothing.
     *
     * @param drainTimeout how long each capability may take to drain in-flight work
     */
    public synchronized void stop(Duration drainTimeout) {
        if (state != State.STARTED) {
            return;
        }
        state = State.STOPPED;
        for (int i = readyOrder.size() - 1; i >= 0; i--) {
            try {
                readyOrder.get(i).drain(drainTimeout);
            } catch (Exception e) {
                System.getLogger(IdentityComposition.class.getName())
                        .log(System.Logger.Level.WARNING, "draining a capability failed", e);
            }
        }
        terminateFirst(readyOrder.size());
    }

    private void terminateFirst(int count) {
        for (int i = count - 1; i >= 0; i--) {
            CapabilityLifecycleHooks module = readyOrder.get(i);
            try {
                module.terminate();
            } catch (RuntimeException e) {
                System.getLogger(IdentityComposition.class.getName()).log(System.Logger.Level.WARNING,
                        "terminating {0} failed: {1}", module.getClass().getSimpleName(), e.getMessage());
            }
        }
    }

    /** The strict route registry; it is frozen once {@link #start()} has completed. */
    public ApiSurfaceRegistry apiSurfaceRegistry() {
        return serviceBoundary.apiSurfaceRegistry();
    }

    /**
     * The handler the transport calls for every request: the route registry, with the connection's peer
     * address kept visible to the rate limit and to the handlers.
     */
    public HttpHandler httpHandler() {
        return PeerAddresses.binding(serviceBoundary.apiSurfaceRegistry());
    }

    /** The admission filter chain the token check and the rate limit are attached to. */
    public RequestFilterChain requestFilterChain() {
        return serviceBoundary.requestFilterChain();
    }

    /**
     * Creates already-verified accounts. For a host's administrator bootstrap; no route of this service
     * exposes it to a caller that has not proved control of the mailbox.
     */
    public CredentialProvisioning credentialProvisioning() {
        return credentialProvisioning;
    }

    /** The verification policy the token check is bound to. */
    public JwtAdmissionPolicy jwtAdmissionPolicy() {
        return jwtPolicy;
    }

    /** The binding that attaches the token check to the filter chain. */
    public JwtServiceBoundaryBinding jwtBinding() {
        return jwtBinding;
    }

    /** The published signing keys; usable to verify this service's tokens in process. */
    public JwksPublisher jwksPublisher() {
        return services.jwks();
    }

    /**
     * A filter that admits a request only when the tenant in the named path parameter is the tenant of
     * the token. A host adds {@code bypassingRoles} for roles that may cross tenants and registers it.
     *
     * @param pathParameter the name of the tenant path parameter
     * @return the filter, not yet registered
     */
    public TenantMembershipFilter tenantMembershipFilter(String pathParameter) {
        return TenantMembershipFilter.pathParameter(pathParameter);
    }

    /**
     * The executor every capability reads and writes through. A host part that is called inside an
     * acceptance or an issue, such as a membership directory or an invitation delivery, writes through it
     * so that its write joins the transaction; a write through the kernel's executor directly, from
     * inside a request, fails because the request's connection is already in a transaction.
     */
    public JoiningTransactionalExecutor transactionalExecutor() {
        return transactions;
    }

    /** The composed capabilities. */
    public IdentityServices services() {
        return services;
    }

    /** Builds an {@link IdentityComposition}. */
    public static final class Builder {

        private ServiceBoundaryCoreModule serviceBoundary;
        private TransactionalExecutor transactionalExecutor;
        private KernelPasswordEncoder passwordEncoder;
        private eu.exeris.caps.credentialstore.spi.NotificationDispatcher notificationDispatcher;
        private MembershipDirectory membershipDirectory;
        private InvitationDelivery invitationDelivery;
        private JobScheduler jobScheduler;
        private IdentityConfig config;
        private Clock clock = Clock.systemUTC();
        private PeerAddressSource peerAddress = PeerAddresses.source();
        private String totpIssuer;
        private final List<RouteContributor> contributors = new ArrayList<>();

        private Builder() {
        }

        /**
         * Uses a host-owned service boundary instead of the one this service creates. It must be in strict
         * route mode.
         *
         * @param module the host's service boundary
         * @return this builder
         */
        public Builder serviceBoundary(ServiceBoundaryCoreModule module) {
            this.serviceBoundary = Objects.requireNonNull(module, "module must not be null");
            return this;
        }

        /** The executor every capability reads and writes through. Required. */
        public Builder transactionalExecutor(TransactionalExecutor executor) {
            this.transactionalExecutor = Objects.requireNonNull(executor, "executor must not be null");
            return this;
        }

        /**
         * The Argon2id encoder password hashes are made and checked with. Required; the library names no
         * driver, so the host supplies it.
         */
        public Builder passwordEncoder(KernelPasswordEncoder encoder) {
            this.passwordEncoder = Objects.requireNonNull(encoder, "encoder must not be null");
            return this;
        }

        /** Delivers verification and password-reset tokens to their recipients. Required. */
        public Builder notificationDispatcher(eu.exeris.caps.credentialstore.spi.NotificationDispatcher dispatcher) {
            this.notificationDispatcher = Objects.requireNonNull(dispatcher, "dispatcher must not be null");
            return this;
        }

        /** Where tenant memberships and roles live. Required. */
        public Builder membershipDirectory(MembershipDirectory directory) {
            this.membershipDirectory = Objects.requireNonNull(directory, "directory must not be null");
            return this;
        }

        /**
         * Hands invitation tokens to the invitees' mailboxes. Optional: without it, issuing an invitation
         * is refused and nothing is stored, because the token would have no way to reach the invitee.
         */
        public Builder invitationDelivery(InvitationDelivery delivery) {
            this.invitationDelivery = Objects.requireNonNull(delivery, "delivery must not be null");
            return this;
        }

        /**
         * Runs the signing-key lifecycle in the background. Required unless the configuration sets manual
         * rotation.
         */
        public Builder jobScheduler(JobScheduler scheduler) {
            this.jobScheduler = scheduler;
            return this;
        }

        /** The validated configuration. Required. */
        public Builder config(IdentityConfig config) {
            this.config = Objects.requireNonNull(config, "config must not be null");
            return this;
        }

        /** The clock lifetimes are measured by; the system UTC clock by default. */
        public Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock must not be null");
            return this;
        }

        /**
         * Where the connection's peer address comes from, for the rate limit. By default the address bound by
         * {@link #httpHandler()}.
         */
        public Builder peerAddress(PeerAddressSource source) {
            this.peerAddress = Objects.requireNonNull(source, "source must not be null");
            return this;
        }

        /** The name authenticator apps show for the second factor; a default when not set. */
        public Builder totpIssuer(String name) {
            this.totpIssuer = name;
            return this;
        }

        /** Adds routes to register before the registry freezes. */
        public Builder routes(RouteContributor contributor) {
            this.contributors.add(Objects.requireNonNull(contributor, "contributor must not be null"));
            return this;
        }

        /**
         * Composes the capabilities and registers the routes.
         *
         * @return the composition, not yet started
         * @throws IllegalStateException    when a required part is missing or the service boundary is not strict
         * @throws IllegalArgumentException when a host-supplied service boundary is not in strict route mode
         */
        public IdentityComposition build() {
            require(config, "config");
            require(transactionalExecutor, "transactionalExecutor");
            require(passwordEncoder, "passwordEncoder");
            require(notificationDispatcher, "notificationDispatcher");
            require(membershipDirectory, "membershipDirectory");
            if (jobScheduler == null && !config.tokenIssuer().manualRotation()) {
                throw new IllegalStateException("jobScheduler is required unless the configuration sets manual "
                        + "signing-key rotation");
            }
            JoiningTransactionalExecutor transactionalExecutor = JoiningTransactionalExecutor.wrap(this.transactionalExecutor);
            ServiceBoundaryCoreModule boundary = serviceBoundary != null
                    ? serviceBoundary
                    : ServiceBoundaryCoreModule.builder().strictRoutes(true).build();
            if (!boundary.isStrictRoutes()) {
                throw new IllegalArgumentException("the service boundary must be in strict route mode: every "
                        + "route has to declare what it requires");
            }
            ApiSurfaceRegistry registry = boundary.apiSurfaceRegistry();
            RequestFilterChain chain = boundary.requestFilterChain();
            var capabilityEnvironment = config.capabilityEnvironment().asMap();

            AuditTrailModule audit = new AuditTrailModule();
            AuditLogSink auditSink = audit.auditLogSink();
            I18nModule i18n = new I18nModule();

            TokenIssuerModule tokenIssuer = new TokenIssuerModule(
                    capabilityEnvironment, transactionalExecutor, jobScheduler,
                    new ApiSurfaceRegistryRegistrar(registry),
                    new eu.exeris.caps.tokenissuer.spi.AuditLogSinkRecorder(auditSink));

            Set<String> anonymous = new LinkedHashSet<>();
            anonymous.add(JWKS_ROUTE);
            for (RouteContributor contributor : contributors) {
                anonymous.addAll(contributor.anonymousRoutes());
            }
            DeferredJwtPolicy policy = new DeferredJwtPolicy();
            JwtServiceBoundaryBinding jwtBinding = JwtServiceBoundaryBinding.of(chain, policy, anonymous);
            JwtValidationModule jwt = new JwtValidationModule(jwtBinding, policy);

            CapabilityLifecycleHooks bindPolicy = new CapabilityLifecycleHooks() {
                @Override
                public void ready() {
                    policy.bind(JwtAdmissionPolicies.fromProperties(
                            config.jwtProperties(), tokenIssuer.jwksPublisher()::getJwksJson));
                }
            };

            RateLimitModule rateLimit = new RateLimitModule(RateLimitServiceBoundaryBinding.of(
                    chain, RateLimitFilterSettings.fromProperties(config.rateLimitProperties()), peerAddress));

            SessionTokenIssuerAdapter sessionTokens = new SessionTokenIssuerAdapter(
                    tokenIssuer.accessTokenIssuer(), membershipDirectory);
            SessionManagementModule sessions = new SessionManagementModule(
                    transactionalExecutor, SessionPolicy.defaults(), sessionTokens, auditSink, clock);

            CredentialStoreModule credentials = new CredentialStoreModule(
                    transactionalExecutor,
                    new AdaptiveArgon2Rehash(passwordEncoder, config.passwordHashing()),
                    notificationDispatcher,
                    new SessionRevocationAdapter(sessions.sessionStore()),
                    new CommitOrderedAuditRecorder(new eu.exeris.caps.credentialstore.spi.AuditLogSinkRecorder(auditSink)),
                    config.credentials().lockout(), config.credentials().token(), config.credentials().password());

            MfaTotpModule mfa = new MfaTotpModule(capabilityEnvironment, transactionalExecutor, auditSink, totpIssuer);
            InvitationsModule invitations = new InvitationsModule(
                    transactionalExecutor, new DirectoryInvitationAdministrators(membershipDirectory));
            FederatedLoginModule federated = new FederatedLoginModule(
                    capabilityEnvironment, transactionalExecutor, null, null, null, auditSink);

            IdentityServices services = new IdentityServices(
                    config, clock,
                    credentials.credentialStore(), credentials.accountVerification(),
                    credentials.credentialRecovery(), credentials.credentialProvisioning(),
                    sessions.sessionStore(), sessions.refreshTokenRotation(), sessionTokens,
                    mfa.getTotpFactorRegistry(), mfa.getTotpVerifier(), mfa.getRecoveryCodes(),
                    mfa.getMfaChallenge(),
                    invitations.invitationService(), membershipDirectory, Optional.ofNullable(invitationDelivery),
                    transactionalExecutor, tokenIssuer.jwksPublisher(),
                    tokenIssuer.signingKeyRotation(), auditSink,
                    i18n.localeResolver(), i18n.translationRegistry());

            for (RouteContributor contributor : contributors) {
                for (ApiSurfaceRoute route : contributor.routes(services)) {
                    registry.registerRoute(route);
                }
            }

            List<CapabilityLifecycleHooks> readyOrder = List.of(
                    audit, i18n, tokenIssuer, bindPolicy, rateLimit, jwt, credentials, mfa, sessions,
                    invitations, federated, boundary);
            return new IdentityComposition(boundary, readyOrder, policy, jwtBinding, services);
        }

        private static void require(Object value, String name) {
            if (value == null) {
                throw new IllegalStateException(name + " is required");
            }
        }
    }
}
