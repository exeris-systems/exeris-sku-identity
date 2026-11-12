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
 * <p>The configured rate-limit groups name the public credential routes of
 * {@link eu.exeris.sku.identity.http.IdentityRoutes}. {@code start} refuses a configured route that no
 * registered route declares, so a host registers those routes, through that contributor or its own,
 * before calling it; a limit on a route that is not served would protect nothing.
 *
 * <p>The schema of the capabilities is applied beforehand, with
 * {@link eu.exeris.sku.identity.persistence.IdentityMigrations}.
 */
public final class IdentityComposition {

    /** The public key-set route the token issuer registers once it is ready. */
    static final String JWKS_ROUTE = "GET /.well-known/jwks.json";

    /**
     * The one budget shared by all the drains of the unwind of a failed start; nothing has been served by
     * then. Each capability is given what is left of it.
     */
    private static final long START_FAILURE_DRAIN_SECONDS = 5;
    private static final Duration START_FAILURE_DRAIN = Duration.ofSeconds(START_FAILURE_DRAIN_SECONDS);

    private final ServiceBoundaryCoreModule serviceBoundary;
    private final List<CapabilityLifecycleHooks> readyOrder;
    private final JwtAdmissionPolicy jwtPolicy;
    private final JwtServiceBoundaryBinding jwtBinding;
    private final CredentialProvisioning credentialProvisioning;
    private final IdentityServices services;
    private final JoiningTransactionalExecutor transactions;
    private State state = State.BUILT;
    private boolean startAttempted;
    private boolean startFailed;

    /**
     * BUILT, then STARTING, STARTED, STOPPING, STOPPED. Every transition happens under this object's
     * monitor, and {@code start} and {@code stop} hold it for their whole run, so STARTING and STOPPING are
     * never observed by another thread: a caller either sees the composition before the operation or after
     * it. A stop from BUILT goes straight to STOPPED, and STOPPED is final.
     */
    private enum State { BUILT, STARTING, STARTED, STOPPING, STOPPED }

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
     * <p>A composition is started at most once, and never after {@link #stop(Duration)}: a stop that came
     * first is final, so the call is refused rather than ignored, because an embedding host that asked for a
     * stop and then started the service would otherwise be left with a service nothing will stop.
     *
     * <p>A capability whose {@code initialize} threw is terminated with the ones initialised before it:
     * {@code CapabilityLifecycleHooks#terminate()} is owed to every capability that entered
     * {@code initialize}, whether or not it completed, and a half-initialised capability is the one most
     * likely to hold something to release. A capability that was never reached is not terminated.
     *
     * <p>The drains of the unwind share one budget of {@value #START_FAILURE_DRAIN_SECONDS} seconds, with the
     * semantics of {@link #stop(Duration)}: a drain that overruns it is interrupted and abandoned, and the
     * terminations always follow.
     * The calling thread's interrupt flag follows the rule stated for {@link #stop(Duration)}, with the
     * start of the unwind in place of the start of the stop.
     *
     * <p>The unwind follows the capability lifecycle contract. When {@code initialize} fails at capability
     * <i>k</i>, the capabilities that completed it are drained in reverse order, <i>k</i> is not drained
     * because it never completed {@code initialize} and so has no intake, and then <i>k</i> and the ones
     * before it are terminated in reverse order. When {@code ready} fails, every capability is drained in
     * reverse order and then every one is terminated. A drain or terminate that throws an exception is
     * logged; an {@link Error} is remembered, the first one with the later ones suppressed, and every
     * remaining capability is still drained and terminated. The failure of the start is the exception
     * thrown, with a cleanup {@link Error} attached to it as suppressed, except that a
     * {@link VirtualMachineError} from the cleanup takes its place and carries the start failure as
     * suppressed.
     *
     * @throws IllegalStateException when the composition has been started, when its start failed, or when it
     *                               has been stopped; the message says which
     * @throws Exception the failure of the capability that did not start
     */
    public synchronized void start() throws Exception {
        if (state == State.BUILT) {
            beginStart();
            return;
        }
        if (state == State.STOPPED && !startAttempted) {
            throw new IllegalStateException("the composition has been stopped before it was started");
        }
        if (startFailed) {
            throw new IllegalStateException("the composition's start failed and it was stopped; a composition "
                    + "is started at most once");
        }
        throw new IllegalStateException(state == State.STOPPED
                ? "the composition has been started and stopped; a composition is started at most once"
                : "the composition has been started");
    }

    /**
     * Starts the composition unless a stop has already been requested, in which case it stays unstarted.
     * This is the call for a host that stops from another thread: the check and the start are one step under
     * the composition's monitor, so a stop either precedes it, and nothing starts, or follows it, and waits
     * for the start to finish and then stops what started.
     *
     * <p>The result is {@code false} exactly when the composition was stopped before it was ever started.
     * A composition whose start failed, or that was started and then stopped, cannot be started again and
     * the call throws, as {@link #start()} does: its state says nothing about a pending stop request.
     *
     * @return {@code true} when the composition started; {@code false} when a stop came first
     * @throws IllegalStateException when the composition has already been started, or its start failed
     * @throws Exception the failure of the capability that did not start
     */
    public synchronized boolean tryStart() throws Exception {
        if (state == State.STOPPED && !startAttempted) {
            return false;
        }
        start();
        return true;
    }

    private void beginStart() throws Exception {
        startAttempted = true;
        state = State.STARTING;
        int entered = 0;
        boolean initialized = false;
        try {
            for (CapabilityLifecycleHooks module : readyOrder) {
                entered++;
                module.initialize();
            }
            initialized = true;
            for (CapabilityLifecycleHooks module : readyOrder) {
                module.ready();
            }
            state = State.STARTED;
        } catch (Exception | Error failure) {
            startFailed = true;
            int drained = initialized ? entered : entered - 1;
            InterruptDebt debt = new InterruptDebt(Thread.currentThread().isInterrupted());
            Error cleanup;
            try {
                cleanup = remember(drainFirst(drained, START_FAILURE_DRAIN, debt), terminateFirst(entered));
            } finally {
                state = State.STOPPED;
                debt.settle();
            }
            if (cleanup instanceof VirtualMachineError && !(failure instanceof VirtualMachineError)) {
                cleanup.addSuppressed(failure);
                throw cleanup;
            }
            if (cleanup != null) {
                failure.addSuppressed(cleanup);
            }
            throw failure;
        }
    }

    /**
     * Drains every capability, then terminates them, in the reverse order of start. Stopping a composition
     * that has not been started records the stop: it stays unstarted and {@link #start()} refuses it
     * afterwards. A stop that arrives while another thread is starting waits for the start to finish and then
     * stops what started. Stopping a stopped composition does nothing.
     *
     * <p>Every capability is drained and then terminated whatever an earlier one threw: an exception from a
     * drain or a terminate is logged by the class of the capability and of the exception, without its
     * message or stack, and an {@link Error} is remembered and rethrown after the last
     * capability has been terminated, the first one with the later ones suppressed, so that a capability whose
     * class cannot be loaded does not leave the ones after it holding their resources.
     *
     * <p>The drains share one budget, {@code drainTimeout}: each capability is passed what remains of it, and
     * a drain that is still running when it is used up is interrupted and abandoned (logged once at
     * {@code WARNING}), after which the next capability is drained, or skipped if nothing remains, and every
     * capability is terminated. A drain runs on the thread that called {@code stop}, which holds this
     * object's monitor: a drain that calls back into this composition re-enters the monitor and cannot
     * deadlock against its own stop. A concurrent second {@code stop} waits for the monitor, and so for the
     * first stop to complete, and then finds the composition stopped and does nothing; the wait is bounded by
     * the budget plus the time the terminations take, provided the drains honour an interrupt. The drain is
     * interrupted, not killed: a drain that ignores the interrupt keeps the stop until it returns, and is
     * never running when its capability's {@code terminate} is called.
     *
     * <p>Interrupts. While no watchdog has fired, the composition never writes the calling thread's interrupt
     * flag during the stop: it neither clears nor sets it, and whatever a drain or a terminate does to the
     * flag stays as that capability left it for the ones that follow. A flag set on entry is therefore
     * visible to the drains and terminates only for as long as none of them consumes it and no watchdog
     * fires; the composition does not set it again between capabilities. When a drain's watchdog fired, the
     * flag is read and cleared in one step at the end of that drain and stays clear for every later drain and
     * every terminate, so that the watchdog's interrupt reaches none of them.
     *
     * <p>On return from {@code stop}, whether it returns normally or throws, the flag is set if it was set
     * when the stop began (read once, on entry), or was set when a watchdog fired, or was set at the end of a
     * drain whose watchdog fired. Otherwise the composition leaves the flag as the capabilities left it. The
     * last of the three cases cannot be told from the watchdog's own interrupt, which a drain may have
     * ignored or restored, and is resolved toward keeping the request: after a stop in which a capability's
     * drain overran its slice and ended with the interrupt flag set, the caller gets the flag set on return
     * although no other source may have interrupted it. A caller must treat an interrupt after such a stop as
     * a request to stop, which it has just carried out.
     *
     * <p>A stop request that arrives during the stop and is consumed by a capability itself before the end of
     * its drain (its blocking call throws {@link InterruptedException}, or it calls
     * {@link Thread#interrupted()}), or by a terminate, is not restored. The requests that are kept are
     * exactly the three above.
     *
     * @param drainTimeout the time all the capabilities together may take to drain in-flight work; a
     *        negative duration, of whatever size, is a budget that is already used up
     * @throws NullPointerException if {@code drainTimeout} is {@code null}, before the composition changes
     *         state and before any capability is drained or terminated
     * @throws Error the first {@code Error} a drain or a terminate threw, after all have been attempted
     */
    public synchronized void stop(Duration drainTimeout) {
        Objects.requireNonNull(drainTimeout, "drainTimeout");
        if (state == State.BUILT) {
            state = State.STOPPED;
            return;
        }
        if (state != State.STARTED) {
            return;
        }
        state = State.STOPPING;
        InterruptDebt debt = new InterruptDebt(Thread.currentThread().isInterrupted());
        Error failure = null;
        try {
            failure = remember(drainFirst(readyOrder.size(), drainTimeout, debt), terminateFirst(readyOrder.size()));
        } finally {
            state = State.STOPPED;
            debt.settle();
        }
        if (failure != null) {
            throw failure;
        }
    }

    /**
     * Drains the first {@code count} capabilities in reverse order, every one of them whatever an earlier
     * one threw, within one budget: a capability is passed what remains of {@code budget}, a drain still
     * running when the budget is used up is interrupted and abandoned, and once nothing remains the later
     * drains are skipped. Each abandoned or skipped drain is logged once at {@code WARNING} by the class of
     * the capability.
     *
     * <p>A drain runs on the calling thread, which keeps the bindings the thread carries, and a watchdog
     * interrupts that thread at the deadline. While no watchdog has fired the flag is not written. After a
     * drain whose watchdog fired the thread's flag is clear, so that no watchdog interrupt reaches the next
     * drain or any terminate, and the interrupt that may be another source's is recorded in {@code debt}, to
     * be set again when the stop or the unwind returns; {@link #drainWithin} states the rule.
     *
     * @return the first {@link Error} a drain threw, with the later ones suppressed; {@code null} when
     *         there was none. An {@link Exception} is logged and goes no further.
     */
    private Error drainFirst(int count, Duration budget, InterruptDebt debt) {
        Error failure = null;
        long deadline = System.nanoTime() + nanos(budget);
        for (int i = count - 1; i >= 0; i--) {
            CapabilityLifecycleHooks module = readyOrder.get(i);
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) {
                System.getLogger(IdentityComposition.class.getName()).log(System.Logger.Level.WARNING,
                        "the drain budget is used up, not draining {0}", module.getClass().getName());
                continue;
            }
            try {
                if (!drainWithin(module, Duration.ofNanos(remaining), debt)) {
                    System.getLogger(IdentityComposition.class.getName()).log(System.Logger.Level.WARNING,
                            "{0} overran the drain budget, its drain was interrupted and abandoned",
                            module.getClass().getName());
                }
            } catch (Exception e) {
                System.getLogger(IdentityComposition.class.getName())
                        .log(System.Logger.Level.WARNING, "draining {0} failed: {1}", module.getClass().getName(),
                                e.getClass().getName());
            } catch (Error e) {
                failure = remember(failure, e);
            }
        }
        return failure;
    }

    /**
     * Runs one drain on the calling thread with a watchdog that interrupts the thread when {@code remaining}
     * has passed, and settles the thread's flag on return as if this were the whole stop: an interrupt that
     * is owed to the caller is set again before the call returns.
     *
     * @return {@code false} when the watchdog interrupted the drain; {@code true} otherwise
     * @throws Exception what the drain threw, unless the watchdog had fired when it threw the
     *         {@link InterruptedException}
     */
    private static boolean drainWithin(CapabilityLifecycleHooks module, Duration remaining) throws Exception {
        InterruptDebt debt = new InterruptDebt(false);
        try {
            return drainWithin(module, remaining, debt);
        } finally {
            debt.settle();
        }
    }

    /**
     * Runs one drain on the calling thread with a watchdog that interrupts the thread when {@code remaining}
     * has passed.
     *
     * <p>The watchdog interrupts under a gate in which it also records whether the thread's flag was already
     * set; the end of the drain closes the same gate, so the watchdog cannot fire after the drain has ended.
     * When it had fired, the closing reads and clears the flag in one step, so every interrupt is either in
     * what was read or arrives after it and stays set. What a drain did with its flag cannot say whose a flag
     * set at the end is, so the rule does not guess:
     * <ul>
     * <li>the watchdog did not fire: the flag is not written, so it is as the drain left it;
     * <li>the watchdog fired: the flag is clear on return, so that the watchdog's interrupt reaches neither
     *     the next drain nor a terminate, and an interrupt is recorded in {@code debt} as owed to the caller
     *     of the stop when the flag was set when the watchdog fired or is set at the end of the drain. The
     *     last case includes the watchdog's own interrupt that the drain ignored or restored; it is kept
     *     rather than lost. A flag set when the stop began is owed through the {@code debt} that the stop
     *     created with it, not through this method.
     * </ul>
     *
     * @param debt where the interrupt owed to the caller of the stop is recorded; this method never sets it
     *        back
     * @return {@code false} when the watchdog interrupted the drain; {@code true} otherwise
     * @throws Exception what the drain threw, unless the watchdog had fired when it threw the
     *         {@link InterruptedException}
     */
    private static boolean drainWithin(CapabilityLifecycleHooks module, Duration remaining, InterruptDebt debt)
            throws Exception {
        Thread caller = Thread.currentThread();
        WatchdogGate gate = new WatchdogGate();
        Thread watchdog = new Thread(() -> {
            try {
                Thread.sleep(remaining);
            } catch (InterruptedException cancelled) {
                Thread.currentThread().interrupt();
                return;
            }
            gate.fire(caller);
        }, "identity-drain-watchdog");
        watchdog.setDaemon(true);
        watchdog.start();
        DrainEnd end = null;
        try {
            module.drain(remaining);
            end = gate.close(caller);
        } catch (InterruptedException interrupted) {
            end = gate.close(caller);
            if (!end.fired()) {
                throw interrupted;
            }
        } catch (Exception | Error thrown) {
            end = gate.close(caller);
            throw thrown;
        } finally {
            if (end == null) {
                end = gate.close(caller);
            }
            watchdog.interrupt();
            if (end.fired()) {
                if (end.flagBeforeFire() || end.flagAtEnd()) {
                    debt.owe();
                }
            }
        }
        return !end.fired();
    }

    /**
     * An interrupt that belongs to the caller of a stop or of a start's unwind: one that was set when the stop
     * or the unwind began, or that a drain's watchdog took off the thread. It is set on the thread by
     * {@link #settle()} when the stop or the unwind returns.
     */
    private static final class InterruptDebt {
        private boolean owed;

        InterruptDebt(boolean owed) {
            this.owed = owed;
        }

        void owe() {
            owed = true;
        }

        void settle() {
            if (owed) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** What the gate recorded at the end of a drain. */
    private record DrainEnd(boolean fired, boolean flagBeforeFire, boolean flagAtEnd) {
    }

    /** The point at which the watchdog fires or the drain ends, whichever comes first; the other then does nothing. */
    private static final class WatchdogGate {
        private boolean over;
        private boolean fired;
        private boolean flagBeforeFire;

        synchronized void fire(Thread caller) {
            if (!over) {
                flagBeforeFire = caller.isInterrupted();
                fired = true;
                caller.interrupt();
            }
        }

        synchronized DrainEnd close(Thread caller) {
            over = true;
            // Read and clear in one step when the watchdog fired: the flag is then the watchdog's or another
            // source's, which the caller is owed, and none can arrive between the read and the clear.
            boolean flagAtEnd = fired ? Thread.interrupted() : caller.isInterrupted();
            return new DrainEnd(fired, flagBeforeFire, flagAtEnd);
        }
    }

    private static long nanos(Duration budget) {
        try {
            return Math.max(0, budget.toNanos());
        } catch (ArithmeticException outOfRange) {
            return budget.isNegative() ? 0 : Long.MAX_VALUE / 4;
        }
    }

    /**
     * Terminates the first {@code count} capabilities in reverse order, every one of them whatever an
     * earlier one threw.
     *
     * @return the first {@link Error} a terminate threw, with the later ones suppressed; {@code null} when
     *         there was none. A {@link RuntimeException} is logged and goes no further.
     */
    private Error terminateFirst(int count) {
        Error failure = null;
        for (int i = count - 1; i >= 0; i--) {
            CapabilityLifecycleHooks module = readyOrder.get(i);
            try {
                module.terminate();
            } catch (RuntimeException e) {
                System.getLogger(IdentityComposition.class.getName()).log(System.Logger.Level.WARNING,
                        "terminating {0} failed: {1}", module.getClass().getName(), e.getClass().getName());
            } catch (Error e) {
                System.getLogger(IdentityComposition.class.getName()).log(System.Logger.Level.WARNING,
                        "terminating {0} failed: {1}", module.getClass().getName(), e.getClass().getName());
                failure = remember(failure, e);
            }
        }
        return failure;
    }

    /** Keeps the first failure and attaches a later one to it; a fatal VM error takes the first place. */
    private static Error remember(Error first, Error next) {
        if (next == null || next == first) {
            return first;
        }
        if (first == null) {
            return next;
        }
        if (next instanceof VirtualMachineError && !(first instanceof VirtualMachineError)) {
            next.addSuppressed(first);
            return next;
        }
        first.addSuppressed(next);
        return first;
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
                    registry, RateLimitFilterSettings.fromProperties(config.rateLimitProperties()), peerAddress));

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
