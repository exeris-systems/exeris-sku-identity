package eu.exeris.sku.identity.http;

import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRoute;
import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpHandler;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.http.RouteRequirement;
import eu.exeris.sku.identity.IdentityServices;
import eu.exeris.sku.identity.RouteContributor;
import eu.exeris.sku.identity.auth.Scopes;
import eu.exeris.sku.identity.config.IdentityConfig;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;

/**
 * The routes of the identity service, each with the requirement the strict registry enforces.
 *
 * <p>A route that admits a caller without a token is declared {@code permitAll()} and named in
 * {@link #anonymousRoutes()}. Every other route needs a verified token, and the subject and the tenant a
 * handler acts for come from that token, or from state the handler has validated itself; no request field
 * names them.
 */
public final class IdentityRoutes implements RouteContributor {

    /** The base path of the credential routes. */
    public static final String BASE = "/api/v1/auth";

    /** Liveness. */
    public static final String HEALTH = "/health";

    private static final String LOGIN = BASE + "/login";
    private static final String MFA_VERIFY = BASE + "/mfa/verify";
    private static final String REFRESH = BASE + "/refresh";
    private static final String PASSWORD_RESET_REQUEST = BASE + "/password/reset-request";
    private static final String PASSWORD_RESET = BASE + "/password/reset";
    private static final String VERIFICATION_SEND = BASE + "/verification/send";
    private static final String VERIFICATION_VERIFY = BASE + "/verification/verify";
    private static final String INVITATIONS_ACCEPT = BASE + "/invitations/accept";
    private static final String PASSWORD_CHANGE = BASE + "/password/change";
    private static final String TOTP_ENROLLMENT = BASE + "/mfa/totp/enrollment";
    private static final String TOTP_CONFIRM = BASE + "/mfa/totp/enrollment/confirm";
    private static final String RECOVERY_CODES = BASE + "/mfa/recovery-codes";
    private static final String SESSIONS = BASE + "/sessions";
    private static final String SESSIONS_REVOKE = BASE + "/sessions/revoke";
    private static final String SESSIONS_REVOKE_ALL = BASE + "/sessions/revoke-all";
    private static final String INVITATIONS = BASE + "/invitations";

    private final IdentityConfig config;

    /**
     * @param config the validated configuration; its CORS origins decide whether preflight routes exist
     */
    public IdentityRoutes(IdentityConfig config) {
        this.config = Objects.requireNonNull(config, "config must not be null");
    }

    /** What a route needs from its caller. */
    private enum Access { ANONYMOUS, AUTHENTICATED, SCOPED }

    /** One row of the route table. */
    private record Entry(HttpMethod method, String path, String action, Access access,
                         Function<Handlers, HttpHandler> handler) {

        RouteRequirement requirement() {
            return switch (access) {
                case ANONYMOUS -> RouteRequirement.permitAll();
                case AUTHENTICATED -> RouteRequirement.authenticated();
                case SCOPED -> RouteRequirement.requiringAnyScope(Set.of(Scopes.INVITATIONS_WRITE));
            };
        }

        String key() {
            return method.name() + " " + path;
        }
    }

    /** The handler classes a row picks from. */
    private record Handlers(AuthHandlers auth, MfaHandlers mfa, SessionHandlers sessions,
                            PasswordHandlers passwords, VerificationHandlers verification,
                            InvitationHandlers invitations) {
    }

    private static final List<Entry> TABLE = List.of(
            new Entry(HttpMethod.GET, HEALTH, "health", Access.ANONYMOUS, null),
            new Entry(HttpMethod.POST, LOGIN, "login", Access.ANONYMOUS, h -> h.auth()::login),
            new Entry(HttpMethod.POST, MFA_VERIFY, "verifyMfa", Access.ANONYMOUS, h -> h.mfa()::verify),
            new Entry(HttpMethod.POST, REFRESH, "refresh", Access.ANONYMOUS, h -> h.auth()::refresh),
            new Entry(HttpMethod.POST, PASSWORD_RESET_REQUEST, "requestPasswordReset", Access.ANONYMOUS,
                    h -> h.passwords()::requestReset),
            new Entry(HttpMethod.POST, PASSWORD_RESET, "resetPassword", Access.ANONYMOUS,
                    h -> h.passwords()::reset),
            new Entry(HttpMethod.POST, VERIFICATION_SEND, "sendVerification", Access.ANONYMOUS,
                    h -> h.verification()::send),
            new Entry(HttpMethod.POST, VERIFICATION_VERIFY, "verifyAccount", Access.ANONYMOUS,
                    h -> h.verification()::verify),
            new Entry(HttpMethod.POST, INVITATIONS_ACCEPT, "acceptInvitation", Access.ANONYMOUS,
                    h -> h.invitations()::accept),
            new Entry(HttpMethod.POST, PASSWORD_CHANGE, "changePassword", Access.AUTHENTICATED,
                    h -> h.passwords()::change),
            new Entry(HttpMethod.POST, TOTP_ENROLLMENT, "beginTotpEnrollment", Access.AUTHENTICATED,
                    h -> h.mfa()::beginEnrollment),
            new Entry(HttpMethod.POST, TOTP_CONFIRM, "confirmTotpEnrollment", Access.AUTHENTICATED,
                    h -> h.mfa()::confirmEnrollment),
            new Entry(HttpMethod.POST, RECOVERY_CODES, "regenerateRecoveryCodes", Access.AUTHENTICATED,
                    h -> h.mfa()::regenerateRecoveryCodes),
            new Entry(HttpMethod.GET, SESSIONS, "listSessions", Access.AUTHENTICATED, h -> h.sessions()::list),
            new Entry(HttpMethod.POST, SESSIONS_REVOKE, "revokeSession", Access.AUTHENTICATED,
                    h -> h.sessions()::revoke),
            new Entry(HttpMethod.POST, SESSIONS_REVOKE_ALL, "revokeAllSessions", Access.AUTHENTICATED,
                    h -> h.sessions()::revokeAll),
            new Entry(HttpMethod.POST, INVITATIONS, "issueInvitation", Access.SCOPED,
                    h -> h.invitations()::issue));

    /**
     * Every route of the table as {@code "METHOD /path"}, without the preflight routes.
     *
     * @return the keys, in table order
     */
    public static List<String> tableKeys() {
        return TABLE.stream().map(Entry::key).toList();
    }

    @Override
    public List<ApiSurfaceRoute> routes(IdentityServices services) {
        JsonBodies bodies = new JsonBodies(JsonBodies.mapper());
        Cors cors = Cors.of(config.corsOrigins());
        Responses responses = new Responses(cors);
        Guard guard = new Guard(responses);
        SessionIssuance sessions = new SessionIssuance(services);
        Handlers handlers = new Handlers(
                new AuthHandlers(services, bodies, responses, sessions),
                new MfaHandlers(services, bodies, responses, sessions),
                new SessionHandlers(services, bodies, responses),
                new PasswordHandlers(services, bodies, responses),
                new VerificationHandlers(services, bodies, responses),
                new InvitationHandlers(services, bodies, responses));
        List<ApiSurfaceRoute> routes = new ArrayList<>();
        Set<String> preflightPaths = new LinkedHashSet<>();
        for (Entry entry : TABLE) {
            HttpHandler body = entry.handler() == null
                    ? health(responses)
                    : entry.handler().apply(handlers);
            HttpHandler handler = entry.access() == Access.ANONYMOUS ? guard.anonymous(body) : guard.authenticated(body);
            routes.add(ApiSurfaceRoute.builder()
                    .method(entry.method())
                    .pathPattern(entry.path())
                    .actionName(entry.action())
                    .requirements(List.of(entry.requirement()))
                    .handler(handler)
                    .build());
            preflightPaths.add(entry.path());
        }
        if (cors.enabled()) {
            for (String path : preflightPaths) {
                routes.add(ApiSurfaceRoute.builder()
                        .method(HttpMethod.OPTIONS)
                        .pathPattern(path)
                        .actionName("preflight " + path)
                        .requirements(List.of(RouteRequirement.permitAll()))
                        .handler(cors::preflight)
                        .build());
            }
        }
        return List.copyOf(routes);
    }

    @Override
    public Set<String> anonymousRoutes() {
        Set<String> anonymous = new LinkedHashSet<>();
        for (Entry entry : TABLE) {
            if (entry.access() == Access.ANONYMOUS) {
                anonymous.add(entry.key());
            }
        }
        if (!config.corsOrigins().isEmpty()) {
            for (Entry entry : TABLE) {
                anonymous.add(HttpMethod.OPTIONS.name() + " " + entry.path());
            }
        }
        return anonymous;
    }

    private static HttpHandler health(Responses responses) {
        return (HttpExchange exchange) ->
                responses.json(exchange, HttpStatus.OK, Responses.object("status", "UP"));
    }
}
