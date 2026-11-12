package eu.exeris.sku.identity.config;

import eu.exeris.caps.credentialstore.api.model.LockoutPolicy;
import eu.exeris.caps.credentialstore.api.model.PasswordPolicy;
import eu.exeris.caps.credentialstore.api.model.TokenPolicy;
import eu.exeris.caps.jwt.api.JwtAdmissionPolicies;
import eu.exeris.caps.ratelimit.api.RateLimitFilterSettings;
import eu.exeris.caps.tokenissuer.api.TokenIssuerConfig;
import eu.exeris.caps.tokenissuer.api.exception.TokenIssuerConfigurationException;
import eu.exeris.kernel.spi.security.credentials.PasswordEncoderConfig;

import java.io.IOException;
import java.io.Reader;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;

/**
 * The identity service's runtime configuration, read from environment variables and an optional
 * properties file.
 *
 * <p>Every setting has one name. The properties file named by {@value #CONFIG_FILE_KEY} uses the same
 * names as the environment, and an environment variable overrides the file. Loading checks every setting
 * and raises one {@link IdentityConfigException} that lists all the problems found, so the service
 * refuses to start rather than start with something the operator did not choose.
 *
 * <p>There is no default issuer, no default audience and no default key material: a deployment names its
 * own issuer and audience, and supplies the key-encryption keyring and the pepper that protect secrets at
 * rest. The access-token issuer and the access-token verifier are one deployment, so the verifier's
 * issuer and audience are the issuer's; the optional {@value #JWT_ISSUER} and {@value #JWT_AUDIENCE}
 * settings exist to be checked against them, never to differ from them.
 *
 * <p>Secret values are not fields of this record. The capabilities that consume them read them from
 * {@link #capabilityEnvironment()}, which does not print its contents.
 *
 * @param http                  listener and request limits
 * @param tokenIssuer           claims, lifetimes and signing-key lifecycle of the access-token issuer
 * @param mfa                   lifetimes of the second-factor challenge
 * @param jwt                   what the verifier requires of an access token
 * @param rateLimit             rate limiting of the public credential routes
 * @param corsOrigins           allowed CORS origins; empty when cross-origin access is off
 * @param credentials           lockout, token and password policies of the credential store
 * @param passwordHashing       Argon2id parameters new password hashes are made with
 * @param capabilityEnvironment the settings the token-issuer, second-factor and federated-login capabilities
 *                              read themselves
 */
public record IdentityConfig(
        Http http,
        TokenIssuerConfig tokenIssuer,
        Mfa mfa,
        Jwt jwt,
        RateLimit rateLimit,
        List<String> corsOrigins,
        Credentials credentials,
        PasswordEncoderConfig passwordHashing,
        CapabilityEnvironment capabilityEnvironment) {

    /** Key naming a properties file that carries any of the settings below. */
    public static final String CONFIG_FILE_KEY = "EXERIS_IDENTITY_CONFIG";

    static final String HTTP_BIND_HOST = "EXERIS_HTTP_BIND_HOST";
    static final String HTTP_PORT = "EXERIS_HTTP_PORT";
    static final String HTTP_MAX_REQUEST_BODY_BYTES = "EXERIS_HTTP_MAX_REQUEST_BODY_BYTES";
    static final String HTTP_MAX_REQUEST_HEADER_COUNT = "EXERIS_HTTP_MAX_REQUEST_HEADER_COUNT";
    static final String HTTP_MAX_REQUEST_HEADER_SIZE = "EXERIS_HTTP_MAX_REQUEST_HEADER_SIZE";

    static final String JWT_ISSUER = "EXERIS_JWT_ISSUER";
    static final String JWT_AUDIENCE = "EXERIS_JWT_AUDIENCE";
    static final String JWT_CLOCK_SKEW_SECONDS = "EXERIS_JWT_CLOCK_SKEW_SECONDS";

    static final String CORS_ALLOWED_ORIGINS = "EXERIS_CORS_ALLOWED_ORIGINS";

    static final String RATELIMIT_TRUSTED_PROXIES = "EXERIS_RATELIMIT_TRUSTED_PROXIES";
    static final String RATELIMIT_FORWARDED_HEADER = "EXERIS_RATELIMIT_FORWARDED_HEADER";
    static final String RATELIMIT_MAX_KEYS = "EXERIS_RATELIMIT_MAX_KEYS";

    static final String LOCKOUT_MAX_ATTEMPTS = "EXERIS_CREDENTIALS_LOCKOUT_MAX_ATTEMPTS";
    static final String LOCKOUT_FAILURE_WINDOW_SECONDS = "EXERIS_CREDENTIALS_LOCKOUT_FAILURE_WINDOW_SECONDS";
    static final String LOCKOUT_DURATION_SECONDS = "EXERIS_CREDENTIALS_LOCKOUT_DURATION_SECONDS";
    static final String TOKEN_VERIFICATION_VALIDITY_SECONDS = "EXERIS_CREDENTIALS_TOKEN_VERIFICATION_VALIDITY_SECONDS";
    static final String TOKEN_RESET_VALIDITY_SECONDS = "EXERIS_CREDENTIALS_TOKEN_RESET_VALIDITY_SECONDS";
    static final String TOKEN_ISSUE_COOLDOWN_SECONDS = "EXERIS_CREDENTIALS_TOKEN_ISSUE_COOLDOWN_SECONDS";
    static final String PASSWORD_MIN_LENGTH = "EXERIS_CREDENTIALS_PASSWORD_MIN_LENGTH";
    static final String PASSWORD_MAX_LENGTH = "EXERIS_CREDENTIALS_PASSWORD_MAX_LENGTH";

    static final String ARGON2_MEMORY_KIB = "EXERIS_PASSWORD_ARGON2_MEMORY_KIB";
    static final String ARGON2_ITERATIONS = "EXERIS_PASSWORD_ARGON2_ITERATIONS";
    static final String ARGON2_PARALLELISM = "EXERIS_PASSWORD_ARGON2_PARALLELISM";

    /** Key material read by the token-issuer capability. */
    static final String TOKEN_ISSUER_KEKS = "EXERIS_TOKEN_ISSUER_KEKS";
    static final String TOKEN_ISSUER_KEKS_FILE = "EXERIS_TOKEN_ISSUER_KEKS_FILE";
    /** Settings read by the second-factor capability. */
    static final String MFA_PEPPER = "EXERIS_MFA_TOTP_PEPPER";
    static final String MFA_PEPPER_FILE = "EXERIS_MFA_TOTP_PEPPER_FILE";
    static final String MFA_KEKS = "EXERIS_MFA_TOTP_KEKS";
    static final String MFA_KEKS_FILE = "EXERIS_MFA_TOTP_KEKS_FILE";
    static final String MFA_CHALLENGE_TTL = "EXERIS_MFA_TOTP_CHALLENGE_TTL";
    static final String MFA_CHALLENGE_MAX_TTL = "EXERIS_MFA_TOTP_CHALLENGE_MAX_TTL";

    /** Key material read by the federated-login capability, which seals its flow state under it. */
    static final String FEDERATED_KEYS = "EXERIS_FEDERATED_LOGIN_STATE_KEYS";
    static final String FEDERATED_KEYS_FILE = "EXERIS_FEDERATED_LOGIN_STATE_KEYS_FILE";

    private static final String TOKEN_ISSUER_PREFIX = "EXERIS_TOKEN_ISSUER_";
    private static final String MFA_PREFIX = "EXERIS_MFA_TOTP_";

    private static final Set<String> TOKEN_ISSUER_KEYS = Set.of(
            TokenIssuerConfig.ENV_ISSUER, TokenIssuerConfig.ENV_AUDIENCE, TokenIssuerConfig.ENV_TOKEN_TTL,
            TokenIssuerConfig.ENV_MAX_TOKEN_TTL, TokenIssuerConfig.ENV_CLOCK_SKEW, TokenIssuerConfig.ENV_KEY_TTL,
            TokenIssuerConfig.ENV_ROTATION_CHECK_INTERVAL, TokenIssuerConfig.ENV_JWKS_MAX_AGE,
            TokenIssuerConfig.ENV_MANUAL_ROTATION, TOKEN_ISSUER_KEKS, TOKEN_ISSUER_KEKS_FILE);

    private static final Set<String> MFA_KEYS = Set.of(
            MFA_PEPPER, MFA_PEPPER_FILE, MFA_KEKS, MFA_KEKS_FILE, MFA_CHALLENGE_TTL, MFA_CHALLENGE_MAX_TTL);

    private static final Set<String> FEDERATED_LOGIN_KEYS = Set.of(FEDERATED_KEYS, FEDERATED_KEYS_FILE);

    /** The rate-limited public credential routes, by group. Every route is a {@code METHOD /path} pair. */
    private static final List<GroupDefault> GROUP_DEFAULTS = List.of(
            new GroupDefault("login", List.of("POST /api/v1/auth/login", "POST /api/v1/auth/mfa/verify"), 5, 60),
            new GroupDefault("refresh", List.of("POST /api/v1/auth/refresh"), 30, 60),
            new GroupDefault("password-reset",
                    List.of("POST /api/v1/auth/password/reset-request", "POST /api/v1/auth/password/reset"), 5, 60),
            new GroupDefault("verification", List.of("POST /api/v1/auth/verification/send"), 5, 60),
            new GroupDefault("invitation-accept", List.of("POST /api/v1/auth/invitations/accept"), 5, 60));

    private static final Set<String> FILE_KEYS = fileKeys();

    /**
     * Listener settings, applied to the kernel's HTTP server.
     *
     * @param bindHost              address to bind; loopback unless the operator chose otherwise
     * @param port                  TCP port
     * @param maxRequestBodyBytes   largest request body the server accepts
     * @param maxRequestHeaderCount most headers a request may carry
     * @param maxRequestHeaderSize  largest single header, in bytes
     */
    public record Http(String bindHost, int port, long maxRequestBodyBytes,
                       int maxRequestHeaderCount, int maxRequestHeaderSize) {
    }

    /**
     * Lifetimes of the second-factor challenge the login flow issues after a correct password.
     *
     * @param challengeTtl    lifetime of a challenge
     * @param challengeMaxTtl longest lifetime any challenge may have
     */
    public record Mfa(Duration challengeTtl, Duration challengeMaxTtl) {
    }

    /**
     * What the access-token verifier requires. The key source is the issuer's own JWKS, read in process.
     *
     * @param issuer     the required {@code iss}; equal to the token issuer's
     * @param audience   the required {@code aud}; equal to the token issuer's
     * @param clockSkew  verifier clock tolerance
     */
    public record Jwt(String issuer, String audience, Duration clockSkew) {
    }

    /**
     * Rate limiting of the public credential routes.
     *
     * @param groups           the limited route groups; every route is limited in exactly one
     * @param trustedProxies   CIDRs whose forwarding header is honoured; empty honours none
     * @param forwardedHeader  the header the trusted proxies write the client address into
     * @param maxKeysPerGroup  bound on live buckets per group
     */
    public record RateLimit(List<Group> groups, List<String> trustedProxies, String forwardedHeader,
                            int maxKeysPerGroup) {

        public RateLimit {
            groups = List.copyOf(groups);
            trustedProxies = List.copyOf(trustedProxies);
        }
    }

    /**
     * One rate-limited route group.
     *
     * @param name           the group name
     * @param routes         the {@code METHOD /path} pairs the group limits
     * @param capacity       requests a client may make in a burst
     * @param refillSeconds  seconds in which a client regains one request
     */
    public record Group(String name, List<String> routes, long capacity, long refillSeconds) {

        public Group {
            routes = List.copyOf(routes);
        }
    }

    /**
     * The credential store's policies.
     *
     * @param lockout   failures that lock an account, and for how long
     * @param token     lifetimes of verification and reset tokens
     * @param password  accepted password length
     */
    public record Credentials(LockoutPolicy lockout, TokenPolicy token, PasswordPolicy password) {
    }

    /**
     * Settings handed to the capabilities that read their own configuration, among them secret
     * material. Its text form never shows the values.
     */
    public static final class CapabilityEnvironment {

        private final Map<String, String> values;

        CapabilityEnvironment(Map<String, String> values) {
            this.values = Map.copyOf(values);
        }

        /** The settings as an environment map, for a capability's environment-taking constructor. */
        public Map<String, String> asMap() {
            return values;
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof CapabilityEnvironment that && values.equals(that.values);
        }

        @Override
        public int hashCode() {
            return values.hashCode();
        }

        @Override
        public String toString() {
            return "CapabilityEnvironment[" + values.size() + " settings, values withheld]";
        }
    }

    private record GroupDefault(String name, List<String> routes, long capacity, long refillSeconds) {

        String key(String suffix) {
            return "EXERIS_RATELIMIT_" + name.toUpperCase(Locale.ROOT).replace('-', '_') + "_" + suffix;
        }
    }

    /**
     * The verifier's settings under the keys {@link JwtAdmissionPolicies#fromProperties} reads.
     *
     * @return the properties; the JWKS is the issuer's own, so no JWKS URI is set
     */
    public Map<String, String> jwtProperties() {
        Map<String, String> properties = new LinkedHashMap<>();
        properties.put(JwtAdmissionPolicies.KEY_ISSUER, jwt.issuer());
        properties.put(JwtAdmissionPolicies.KEY_AUDIENCE, jwt.audience());
        properties.put(JwtAdmissionPolicies.KEY_CLOCK_SKEW_SECONDS, Long.toString(jwt.clockSkew().toSeconds()));
        return Map.copyOf(properties);
    }

    /**
     * The rate-limit settings under the keys {@link RateLimitFilterSettings#fromProperties} reads.
     *
     * @return the properties
     */
    public Map<String, String> rateLimitProperties() {
        return rateLimitProperties(rateLimit);
    }

    private static Map<String, String> rateLimitProperties(RateLimit rateLimit) {
        Map<String, String> properties = new LinkedHashMap<>();
        List<String> names = new ArrayList<>();
        for (Group group : rateLimit.groups()) {
            names.add(group.name());
            String prefix = RateLimitFilterSettings.KEY_GROUP_PREFIX + group.name() + ".";
            properties.put(prefix + "routes", String.join(",", group.routes()));
            properties.put(prefix + "capacity", Long.toString(group.capacity()));
            properties.put(prefix + "refill-seconds", Long.toString(group.refillSeconds()));
        }
        properties.put(RateLimitFilterSettings.KEY_GROUPS, String.join(",", names));
        properties.put(RateLimitFilterSettings.KEY_TRUSTED_PROXIES, String.join(",", rateLimit.trustedProxies()));
        properties.put(RateLimitFilterSettings.KEY_FORWARDED_HEADER, rateLimit.forwardedHeader());
        properties.put(RateLimitFilterSettings.KEY_MAX_KEYS, Integer.toString(rateLimit.maxKeysPerGroup()));
        return Map.copyOf(properties);
    }

    /**
     * Reads the configuration from the process environment and the file it names.
     *
     * @return the validated configuration
     * @throws IdentityConfigException when a setting is missing or unusable
     */
    public static IdentityConfig load() {
        return load(System.getenv());
    }

    /**
     * Reads the configuration from {@code environment} and the file it names.
     *
     * @param environment the environment variables; they override the file
     * @return the validated configuration
     * @throws IdentityConfigException when a setting is missing or unusable
     */
    public static IdentityConfig load(Map<String, String> environment) {
        Map<String, String> values = new LinkedHashMap<>();
        String file = environment.get(CONFIG_FILE_KEY);
        if (file != null && !file.isBlank()) {
            values.putAll(readFile(file.trim()));
        }
        for (Map.Entry<String, String> entry : environment.entrySet()) {
            if (FILE_KEYS.contains(entry.getKey()) && entry.getValue() != null && !entry.getValue().isBlank()) {
                values.put(entry.getKey(), entry.getValue().trim());
            }
        }
        return from(values);
    }

    /**
     * Builds the configuration from already merged settings.
     *
     * @param values setting name to value; a blank value counts as unset
     * @return the validated configuration
     * @throws IdentityConfigException listing every setting that is missing or unusable
     */
    public static IdentityConfig from(Map<String, String> values) {
        Source in = new Source(values);

        Http http = new Http(
                in.string(HTTP_BIND_HOST, "127.0.0.1"),
                in.integer(HTTP_PORT, 8080, 1, 65_535),
                in.longValue(HTTP_MAX_REQUEST_BODY_BYTES, 65_536L, 1, 16L * 1024 * 1024),
                in.integer(HTTP_MAX_REQUEST_HEADER_COUNT, 100, 1, 10_000),
                in.integer(HTTP_MAX_REQUEST_HEADER_SIZE, 8_192, 1, 1_048_576));

        TokenIssuerConfig tokenIssuer = tokenIssuer(in);
        in.secret(TOKEN_ISSUER_KEKS, TOKEN_ISSUER_KEKS_FILE, "the key-encryption keyring of the signing keys");
        in.secret(MFA_KEKS, MFA_KEKS_FILE, "the key-encryption keyring of the TOTP secrets");
        in.secret(MFA_PEPPER, MFA_PEPPER_FILE, "the pepper of the recovery-code and challenge hashes");
        in.secret(FEDERATED_KEYS, FEDERATED_KEYS_FILE, "the keyring that seals federated-login flow state");
        Mfa mfa = mfa(in);

        Jwt jwt = jwt(in, tokenIssuer);

        List<String> corsOrigins = in.origins(CORS_ALLOWED_ORIGINS);
        RateLimit rateLimit = rateLimit(in);
        Credentials credentials = credentials(in);
        PasswordEncoderConfig hashing = passwordHashing(in);

        in.fail();
        return new IdentityConfig(http, tokenIssuer, mfa, jwt, rateLimit, corsOrigins, credentials, hashing,
                new CapabilityEnvironment(capabilityValues(values)));
    }

    private static TokenIssuerConfig tokenIssuer(Source in) {
        String issuer = in.string(TokenIssuerConfig.ENV_ISSUER, "");
        String audience = in.string(TokenIssuerConfig.ENV_AUDIENCE, "");
        if (issuer.isEmpty()) {
            in.problem(TokenIssuerConfig.ENV_ISSUER + " is required and has no default: it names this deployment");
        }
        if (audience.isEmpty()) {
            in.problem(TokenIssuerConfig.ENV_AUDIENCE + " is required and has no default: it names who the tokens are for");
        }
        if (issuer.isEmpty() || audience.isEmpty()) {
            return null;
        }
        try {
            return TokenIssuerConfig.fromEnvironment(in.subset(TOKEN_ISSUER_PREFIX));
        } catch (TokenIssuerConfigurationException e) {
            in.problem(e.getMessage());
            return null;
        }
    }

    private static Mfa mfa(Source in) {
        Duration ttl = in.duration(MFA_CHALLENGE_TTL, Duration.ofMinutes(5));
        Duration maxTtl = in.duration(MFA_CHALLENGE_MAX_TTL, Duration.ofMinutes(10));
        if (ttl != null && maxTtl != null && ttl.compareTo(maxTtl) > 0) {
            in.problem(MFA_CHALLENGE_TTL + " must not exceed " + MFA_CHALLENGE_MAX_TTL);
        }
        return new Mfa(ttl, maxTtl);
    }

    private static Jwt jwt(Source in, TokenIssuerConfig tokenIssuer) {
        String issuer = in.string(JWT_ISSUER, "");
        String audience = in.string(JWT_AUDIENCE, "");
        Duration skew = Duration.ofSeconds(in.longValue(JWT_CLOCK_SKEW_SECONDS, 30, 0, 3_600));
        if (tokenIssuer == null) {
            return null;
        }
        if (!issuer.isEmpty() && !issuer.equals(tokenIssuer.issuer())) {
            in.problem(JWT_ISSUER + " must equal " + TokenIssuerConfig.ENV_ISSUER
                    + ": tokens the service issues must pass the service's own verifier");
        }
        if (!audience.isEmpty() && !audience.equals(tokenIssuer.audience())) {
            in.problem(JWT_AUDIENCE + " must equal " + TokenIssuerConfig.ENV_AUDIENCE
                    + ": tokens the service issues must pass the service's own verifier");
        }
        return new Jwt(tokenIssuer.issuer(), tokenIssuer.audience(), skew);
    }

    private static RateLimit rateLimit(Source in) {
        List<Group> groups = new ArrayList<>();
        for (GroupDefault d : GROUP_DEFAULTS) {
            groups.add(new Group(d.name(), d.routes(),
                    in.longValue(d.key("CAPACITY"), d.capacity(), 1, 1_000_000),
                    in.longValue(d.key("REFILL_SECONDS"), d.refillSeconds(), 1, 86_400)));
        }
        List<String> proxies = in.list(RATELIMIT_TRUSTED_PROXIES);
        String header = in.string(RATELIMIT_FORWARDED_HEADER, "x-forwarded-for").toLowerCase(Locale.ROOT);
        int maxKeys = in.integer(RATELIMIT_MAX_KEYS, RateLimitFilterSettings.DEFAULT_MAX_KEYS, 1, 100_000_000);
        RateLimit rateLimit = new RateLimit(groups, proxies, header, maxKeys);
        try {
            RateLimitFilterSettings.fromProperties(rateLimitProperties(rateLimit));
        } catch (IllegalStateException | IllegalArgumentException e) {
            in.problem("rate limiting: " + e.getMessage() + " (" + RATELIMIT_TRUSTED_PROXIES + ", "
                    + RATELIMIT_FORWARDED_HEADER + ")");
        }
        return rateLimit;
    }

    private static Credentials credentials(Source in) {
        LockoutPolicy defaultLockout = LockoutPolicy.defaults();
        TokenPolicy defaultToken = TokenPolicy.defaults();
        PasswordPolicy defaultPassword = PasswordPolicy.defaults();

        LockoutPolicy lockout = null;
        long attempts = in.longValue(LOCKOUT_MAX_ATTEMPTS, defaultLockout.maxAttempts(), 1, 1_000);
        long window = in.longValue(LOCKOUT_FAILURE_WINDOW_SECONDS, defaultLockout.failureWindow().toSeconds(), 1,
                Duration.ofDays(3650).toSeconds());
        long lock = in.longValue(LOCKOUT_DURATION_SECONDS, defaultLockout.lockoutDuration().toSeconds(), 1,
                Duration.ofDays(3650).toSeconds());
        try {
            lockout = new LockoutPolicy((int) attempts, Duration.ofSeconds(window), Duration.ofSeconds(lock));
        } catch (IllegalArgumentException e) {
            in.problem("credential lockout: " + e.getMessage());
        }

        TokenPolicy token = null;
        long verification = in.longValue(TOKEN_VERIFICATION_VALIDITY_SECONDS,
                defaultToken.verificationValidity().toSeconds(), 1, Duration.ofDays(3650).toSeconds());
        long reset = in.longValue(TOKEN_RESET_VALIDITY_SECONDS,
                defaultToken.resetValidity().toSeconds(), 1, Duration.ofDays(3650).toSeconds());
        long cooldown = in.longValue(TOKEN_ISSUE_COOLDOWN_SECONDS,
                defaultToken.issueCooldown().toSeconds(), 1, Duration.ofDays(3650).toSeconds());
        try {
            token = new TokenPolicy(Duration.ofSeconds(verification), Duration.ofSeconds(reset),
                    Duration.ofSeconds(cooldown));
        } catch (IllegalArgumentException e) {
            in.problem("credential tokens: " + e.getMessage());
        }

        PasswordPolicy password = null;
        long min = in.longValue(PASSWORD_MIN_LENGTH, defaultPassword.minLength(), 1, PasswordPolicy.HARD_MAX_LENGTH);
        long max = in.longValue(PASSWORD_MAX_LENGTH, defaultPassword.maxLength(), 1, PasswordPolicy.HARD_MAX_LENGTH);
        try {
            password = new PasswordPolicy((int) min, (int) max);
        } catch (IllegalArgumentException e) {
            in.problem("password length: " + e.getMessage() + " (" + PASSWORD_MIN_LENGTH + ", "
                    + PASSWORD_MAX_LENGTH + ")");
        }
        return new Credentials(lockout, token, password);
    }

    private static PasswordEncoderConfig passwordHashing(Source in) {
        PasswordEncoderConfig d = PasswordEncoderConfig.defaults();
        int memory = in.integer(ARGON2_MEMORY_KIB, d.memoryCostKib(), 8_192, 4_194_304);
        int iterations = in.integer(ARGON2_ITERATIONS, d.iterations(), 1, 100);
        int parallelism = in.integer(ARGON2_PARALLELISM, d.parallelism(), 1, 64);
        try {
            return new PasswordEncoderConfig(memory, iterations, parallelism, d.hashLength());
        } catch (IllegalArgumentException e) {
            in.problem("password hashing: " + e.getMessage());
            return null;
        }
    }

    private static Map<String, String> capabilityValues(Map<String, String> values) {
        Map<String, String> subset = new TreeMap<>();
        for (Map.Entry<String, String> entry : values.entrySet()) {
            String key = entry.getKey();
            if ((TOKEN_ISSUER_KEYS.contains(key) || MFA_KEYS.contains(key) || FEDERATED_LOGIN_KEYS.contains(key))
                    && entry.getValue() != null && !entry.getValue().isBlank()) {
                subset.put(key, entry.getValue().trim());
            }
        }
        return subset;
    }

    private static Set<String> fileKeys() {
        Set<String> keys = new HashSet<>(Set.of(
                HTTP_BIND_HOST, HTTP_PORT, HTTP_MAX_REQUEST_BODY_BYTES, HTTP_MAX_REQUEST_HEADER_COUNT,
                HTTP_MAX_REQUEST_HEADER_SIZE, JWT_ISSUER, JWT_AUDIENCE, JWT_CLOCK_SKEW_SECONDS,
                CORS_ALLOWED_ORIGINS, RATELIMIT_TRUSTED_PROXIES, RATELIMIT_FORWARDED_HEADER, RATELIMIT_MAX_KEYS,
                LOCKOUT_MAX_ATTEMPTS, LOCKOUT_FAILURE_WINDOW_SECONDS, LOCKOUT_DURATION_SECONDS,
                TOKEN_VERIFICATION_VALIDITY_SECONDS, TOKEN_RESET_VALIDITY_SECONDS, TOKEN_ISSUE_COOLDOWN_SECONDS,
                PASSWORD_MIN_LENGTH, PASSWORD_MAX_LENGTH, ARGON2_MEMORY_KIB, ARGON2_ITERATIONS,
                ARGON2_PARALLELISM));
        keys.addAll(TOKEN_ISSUER_KEYS);
        keys.addAll(MFA_KEYS);
        keys.addAll(FEDERATED_LOGIN_KEYS);
        for (GroupDefault d : GROUP_DEFAULTS) {
            keys.add(d.key("CAPACITY"));
            keys.add(d.key("REFILL_SECONDS"));
        }
        return Set.copyOf(keys);
    }

    /** A setting name as the file may carry it: the product prefix and then capitals, digits and underscores. */
    private static final java.util.regex.Pattern SETTING_NAME = java.util.regex.Pattern.compile(
            "EXERIS_[A-Z0-9_]{0,80}");

    /**
     * Reads the settings of the file named by {@value #CONFIG_FILE_KEY}. A message about the file names that
     * setting and a line number; it never quotes the path, a line or a key that is not a known setting name,
     * because an operator may have pasted a secret in place of any of them.
     */
    private static Map<String, String> readFile(String named) {
        List<String> lines;
        try {
            lines = Files.readAllLines(Path.of(named), StandardCharsets.UTF_8);
        } catch (IOException | RuntimeException e) {
            throw new IdentityConfigException(CONFIG_FILE_KEY + " names a file that cannot be read.");
        }
        Map<String, String> values = new LinkedHashMap<>();
        List<String> unknown = new ArrayList<>();
        for (int i = 0; i < lines.size(); i++) {
            int first = i + 1;
            StringBuilder logical = new StringBuilder(lines.get(i));
            boolean comment = lines.get(i).stripLeading().startsWith("#") || lines.get(i).stripLeading().startsWith("!");
            while (!comment && continues(logical) && i + 1 < lines.size()) {
                logical.setLength(logical.length() - 1);
                logical.append(lines.get(++i).stripLeading());
            }
            Properties one = new Properties();
            try {
                one.load(new java.io.StringReader(logical.toString()));
            } catch (IOException | RuntimeException e) {
                unknown.add(CONFIG_FILE_KEY + " line " + first + " is not a valid line of a properties file.");
                continue;
            }
            for (String key : one.stringPropertyNames()) {
                if (!FILE_KEYS.contains(key)) {
                    unknown.add(SETTING_NAME.matcher(key).matches()
                            ? CONFIG_FILE_KEY + " line " + first + " carries an unknown setting: " + key
                            : CONFIG_FILE_KEY + " line " + first + " is not a setting.");
                    continue;
                }
                String value = one.getProperty(key).trim();
                if (!value.isEmpty()) {
                    values.put(key, value);
                }
            }
        }
        if (!unknown.isEmpty()) {
            throw new IdentityConfigException(unknown);
        }
        return values;
    }

    /** Whether a physical line ends in an odd number of backslashes, which joins it to the next one. */
    private static boolean continues(CharSequence line) {
        int backslashes = 0;
        for (int i = line.length() - 1; i >= 0 && line.charAt(i) == '\\'; i--) {
            backslashes++;
        }
        return backslashes % 2 == 1;
    }

    /** Typed access to the merged settings; every error is recorded against its setting, none is thrown. */
    private static final class Source {
        private final Map<String, String> values;
        private final List<String> problems = new ArrayList<>();

        Source(Map<String, String> values) {
            this.values = values;
        }

        void problem(String text) {
            problems.add(text);
        }

        void fail() {
            if (!problems.isEmpty()) {
                throw new IdentityConfigException(problems);
            }
        }

        Map<String, String> subset(String prefix) {
            Map<String, String> subset = new LinkedHashMap<>();
            for (Map.Entry<String, String> entry : values.entrySet()) {
                if (entry.getKey().startsWith(prefix)) {
                    subset.put(entry.getKey(), entry.getValue());
                }
            }
            return subset;
        }

        String string(String key, String fallback) {
            String value = values.get(key);
            return value == null || value.isBlank() ? fallback : value.trim();
        }

        List<String> list(String key) {
            List<String> items = new ArrayList<>();
            for (String item : string(key, "").split(",")) {
                if (!item.isBlank()) {
                    items.add(item.trim());
                }
            }
            return List.copyOf(items);
        }

        long longValue(String key, long fallback, long min, long max) {
            String value = values.get(key);
            if (value == null || value.isBlank()) {
                return fallback;
            }
            long parsed;
            try {
                parsed = Long.parseLong(value.trim());
            } catch (NumberFormatException e) {
                problem(key + " must be a whole number");
                return fallback;
            }
            if (parsed < min || parsed > max) {
                problem(key + " must be between " + min + " and " + max + ", not " + parsed);
                return fallback;
            }
            return parsed;
        }

        int integer(String key, int fallback, int min, int max) {
            return (int) longValue(key, fallback, min, max);
        }

        Duration duration(String key, Duration fallback) {
            String value = values.get(key);
            if (value == null || value.isBlank()) {
                return fallback;
            }
            try {
                Duration parsed = Duration.parse(value.trim());
                if (parsed.isZero() || parsed.isNegative()) {
                    problem(key + " must be a positive ISO-8601 duration such as PT5M");
                    return fallback;
                }
                return parsed;
            } catch (DateTimeParseException e) {
                problem(key + " must be an ISO-8601 duration such as PT5M");
                return fallback;
            }
        }

        /** A secret comes from exactly one of an inline value and a file; the file must be readable. */
        void secret(String inlineKey, String fileKey, String what) {
            boolean inline = !string(inlineKey, "").isEmpty();
            String file = string(fileKey, "");
            if (inline && !file.isEmpty()) {
                problem("set either " + inlineKey + " or " + fileKey + ", not both");
            } else if (!inline && file.isEmpty()) {
                problem(inlineKey + " or " + fileKey + " is required: " + what + " has no default");
            } else if (!file.isEmpty() && !readable(file)) {
                problem(fileKey + " names a file that cannot be read.");
            }
        }

        private static boolean readable(String file) {
            try {
                Path path = Path.of(file);
                return Files.isRegularFile(path) && Files.isReadable(path);
            } catch (RuntimeException invalid) {
                return false;
            }
        }

        /** Browser origins: {@code scheme://host[:port]} with an http or https scheme, no path, never a wildcard. */
        List<String> origins(String key) {
            List<String> origins = new ArrayList<>();
            int position = 0;
            for (String origin : list(key)) {
                position++;
                if (origin.equals("*")) {
                    problem(key + " must list origins; a wildcard is refused");
                    continue;
                }
                URI uri;
                try {
                    uri = new URI(origin);
                } catch (URISyntaxException e) {
                    problem(key + ": entry " + position + " is not a URI");
                    continue;
                }
                String scheme = uri.getScheme();
                boolean plain = uri.getHost() != null && uri.getUserInfo() == null && uri.getQuery() == null
                        && uri.getFragment() == null && (uri.getRawPath() == null || uri.getRawPath().isEmpty());
                if (!plain || !("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
                    problem(key + ": entry " + position + " is not an origin (http:// or https://, host and optional "
                            + "port, nothing else)");
                    continue;
                }
                origins.add(origin);
            }
            return List.copyOf(origins);
        }
    }
}
