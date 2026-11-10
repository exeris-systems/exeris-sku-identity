package eu.exeris.sku.identity.support;

import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRegistry;
import eu.exeris.kernel.community.security.Argon2idPasswordEncoder;
import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.caps.ratelimit.api.PeerAddressSource;
import eu.exeris.sku.identity.IdentityComposition;
import eu.exeris.sku.identity.config.IdentityConfig;
import eu.exeris.sku.identity.http.IdentityRoutes;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * The whole service over a real database: the composition with the identity routes registered, a recording
 * notification dispatcher and an in-memory membership directory. Requests go through the strict registry,
 * so every admission filter and route requirement applies.
 */
public final class IdentityHarness implements AutoCloseable {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final String[] RATE_LIMIT_GROUPS = {
            "LOGIN", "REFRESH", "PASSWORD_RESET", "VERIFICATION", "INVITATION_ACCEPT"};

    /** An account the harness created. */
    public record Account(UUID subject, String email, String password) {
    }

    /** The service's state a test can look at. */
    public final PostgresSupport.Database database;
    public final InMemoryMembershipDirectory directory;
    public final RecordingNotificationDispatcher notifications;
    public final IdentityComposition composition;
    public final IdentityConfig config;
    private final Map<String, String> env;

    private IdentityHarness(PostgresSupport.Database database, InMemoryMembershipDirectory directory,
                            RecordingNotificationDispatcher notifications, IdentityComposition composition,
                            IdentityConfig config, Map<String, String> env) {
        this.env = env;
        this.database = database;
        this.directory = directory;
        this.notifications = notifications;
        this.composition = composition;
        this.config = config;
    }

    /** A started service with rate limits too high to interfere and no CORS origin. */
    public static IdentityHarness start() throws Exception {
        return start(Map.of());
    }

    /**
     * A started service.
     *
     * @param overrides settings that replace the test defaults
     */
    public static IdentityHarness start(Map<String, String> overrides) throws Exception {
        Map<String, String> env = new HashMap<>(TestConfig.env());
        for (String group : RATE_LIMIT_GROUPS) {
            env.put("EXERIS_RATELIMIT_" + group + "_CAPACITY", "100000");
        }
        env.putAll(overrides);
        return start(env, PostgresSupport.newDatabase());
    }

    /**
     * A second service over the same database and key material, with some settings changed, as after a
     * configuration change and a restart.
     *
     * @param overrides settings that replace this service's
     */
    public IdentityHarness restartedWith(Map<String, String> overrides) throws Exception {
        Map<String, String> changed = new HashMap<>(env);
        changed.putAll(overrides);
        return start(changed, database);
    }

    private static IdentityHarness start(Map<String, String> env, PostgresSupport.Database database)
            throws Exception {
        IdentityConfig config = IdentityConfig.load(env);
        InMemoryMembershipDirectory directory = new InMemoryMembershipDirectory();
        RecordingNotificationDispatcher notifications = new RecordingNotificationDispatcher();
        IdentityComposition composition = IdentityComposition.builder()
                .config(config)
                .transactionalExecutor(new JdbcTransactionalExecutor(database))
                .passwordEncoder(new Argon2idPasswordEncoder(config.passwordHashing()))
                .notificationDispatcher(notifications)
                .membershipDirectory(directory)
                .routes(new IdentityRoutes(config))
                .build();
        composition.start();
        return new IdentityHarness(database, directory, notifications, composition, config, Map.copyOf(env));
    }

    /** The registry, for reading the routes. Requests go through {@link #send}, which binds the peer address. */
    public ApiSurfaceRegistry registry() {
        return composition.apiSurfaceRegistry();
    }

    @Override
    public void close() {
        composition.stop(Duration.ofSeconds(1));
    }

    /** Sends a request with a JSON body built from the map, and returns the answered exchange. */
    public TestExchange post(String path, Map<String, ?> body, HttpHeader... headers) {
        TestExchange exchange = TestExchange.json(HttpMethod.POST, path, write(body), headers);
        composition.httpHandler().handle(exchange);
        return exchange;
    }

    /** Sends a request without a body. */
    public TestExchange send(HttpMethod method, String path, HttpHeader... headers) {
        TestExchange exchange = TestExchange.of(method, path, headers);
        composition.httpHandler().handle(exchange);
        return exchange;
    }

    /** Sends a prepared exchange. */
    public TestExchange send(TestExchange exchange) {
        composition.httpHandler().handle(exchange);
        return exchange;
    }

    public static HttpHeader bearer(String token) {
        return new HttpHeader("Authorization", "Bearer " + token);
    }

    /** The response body as a JSON tree. */
    public static JsonNode json(TestExchange exchange) {
        return JSON.readTree(exchange.body());
    }

    public static String write(Object value) {
        return JSON.writeValueAsString(value);
    }

    /** Creates a verified account with a random address and password. */
    public Account account() {
        UUID subject = UUID.randomUUID();
        String email = "user-" + UUID.randomUUID().toString().substring(0, 12) + "@example.test";
        String password = new String(TestConfig.randomPassword());
        composition.credentialProvisioning().provisionVerified(subject, email, password.toCharArray());
        return new Account(subject, email, password);
    }

    /** Creates a verified account that is a member of the tenant with the role. */
    public Account member(UUID tenant, String role) {
        Account account = account();
        directory.grant(tenant, account.subject(), role);
        return account;
    }

    /** The body of a login request. */
    public static Map<String, Object> credentials(Account account) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("email", account.email());
        body.put("password", account.password());
        return body;
    }

    /** Signs in and returns the response tree; the account must have no second factor. */
    public JsonNode login(Account account) {
        TestExchange exchange = post("/api/v1/auth/login", credentials(account));
        if (exchange.code() != 200) {
            throw new IllegalStateException("login answered " + exchange.code());
        }
        return json(exchange);
    }

    /** Signs in and returns the access token. */
    public String accessToken(Account account) {
        return login(account).get("accessToken").stringValue();
    }
}
