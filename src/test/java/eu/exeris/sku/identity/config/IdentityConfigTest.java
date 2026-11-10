package eu.exeris.sku.identity.config;

import eu.exeris.caps.jwt.api.JwtAdmissionPolicies;
import eu.exeris.caps.ratelimit.api.RateLimitFilterSettings;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("IdentityConfig")
class IdentityConfigTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ISSUER = "https://id.example.test";
    private static final String AUDIENCE = "example-api";

    private static String randomBase64(int bytes) {
        byte[] raw = new byte[bytes];
        RANDOM.nextBytes(raw);
        return Base64.getEncoder().encodeToString(raw);
    }

    /** A complete, valid environment; key material is generated for each call. */
    private static Map<String, String> env(String... kv) {
        Map<String, String> m = new HashMap<>();
        m.put("EXERIS_TOKEN_ISSUER_ISSUER", ISSUER);
        m.put("EXERIS_TOKEN_ISSUER_AUDIENCE", AUDIENCE);
        m.put("EXERIS_TOKEN_ISSUER_KEKS", "k1:" + randomBase64(32));
        m.put("EXERIS_MFA_TOTP_KEKS", "k1:" + randomBase64(32));
        m.put("EXERIS_MFA_TOTP_PEPPER", randomBase64(32));
        m.put("EXERIS_FEDERATED_LOGIN_STATE_KEYS", "k1:" + randomBase64(32));
        for (int i = 0; i < kv.length; i += 2) {
            if (kv[i + 1] == null) {
                m.remove(kv[i]);
            } else {
                m.put(kv[i], kv[i + 1]);
            }
        }
        return m;
    }

    @Test
    @DisplayName("Defaults are closed: loopback bind, no CORS origins, no trusted proxies, issuer values carried through")
    void defaultsAreClosed() {
        IdentityConfig c = IdentityConfig.load(env());

        assertThat(c.http().bindHost()).isEqualTo("127.0.0.1");
        assertThat(c.http().port()).isEqualTo(8080);
        assertThat(c.http().maxRequestBodyBytes()).isEqualTo(65_536L);
        assertThat(c.corsOrigins()).isEmpty();
        assertThat(c.rateLimit().trustedProxies()).isEmpty();
        assertThat(c.tokenIssuer().issuer()).isEqualTo(ISSUER);
        assertThat(c.tokenIssuer().audience()).isEqualTo(AUDIENCE);
        assertThat(c.jwt().issuer()).isEqualTo(ISSUER);
        assertThat(c.jwt().audience()).isEqualTo(AUDIENCE);
        assertThat(c.mfa().challengeTtl()).isEqualTo(Duration.ofMinutes(5));
        assertThat(c.credentials().lockout().maxAttempts()).isEqualTo(5);
        assertThat(c.credentials().password().minLength()).isEqualTo(8);
        assertThat(c.passwordHashing().memoryCostKib()).isEqualTo(65_536);
    }

    @Test
    @DisplayName("A missing issuer, audience and every secret are reported together, without defaults")
    void everyProblemIsListed() {
        Map<String, String> bare = new HashMap<>();
        bare.put("EXERIS_HTTP_PORT", "70000");

        assertThatThrownBy(() -> IdentityConfig.load(bare))
                .isInstanceOf(IdentityConfigException.class)
                .satisfies(e -> {
                    String message = e.getMessage();
                    assertThat(message).contains("EXERIS_TOKEN_ISSUER_ISSUER", "EXERIS_TOKEN_ISSUER_AUDIENCE",
                            "EXERIS_TOKEN_ISSUER_KEKS", "EXERIS_MFA_TOTP_KEKS", "EXERIS_MFA_TOTP_PEPPER",
                            "EXERIS_FEDERATED_LOGIN_STATE_KEYS", "EXERIS_HTTP_PORT");
                    assertThat(((IdentityConfigException) e).problems()).hasSize(7);
                });
    }

    @Test
    @DisplayName("A secret comes from exactly one of an inline value and a readable file")
    void secretSources(@TempDir Path dir) throws Exception {
        Path keks = dir.resolve("keks");
        Files.writeString(keks, "k1:" + randomBase64(32));

        IdentityConfig fromFile = IdentityConfig.load(env(
                "EXERIS_TOKEN_ISSUER_KEKS", null, "EXERIS_TOKEN_ISSUER_KEKS_FILE", keks.toString()));
        assertThat(fromFile.capabilityEnvironment().asMap())
                .containsKey("EXERIS_TOKEN_ISSUER_KEKS_FILE")
                .doesNotContainKey("EXERIS_TOKEN_ISSUER_KEKS");

        assertThatThrownBy(() -> IdentityConfig.load(env("EXERIS_TOKEN_ISSUER_KEKS_FILE", keks.toString())))
                .isInstanceOf(IdentityConfigException.class)
                .hasMessageContaining("not both");
        assertThatThrownBy(() -> IdentityConfig.load(env(
                "EXERIS_TOKEN_ISSUER_KEKS", null,
                "EXERIS_TOKEN_ISSUER_KEKS_FILE", dir.resolve("absent").toString())))
                .isInstanceOf(IdentityConfigException.class)
                .hasMessageContaining("EXERIS_TOKEN_ISSUER_KEKS_FILE")
                .hasMessageContaining("cannot be read");
    }

    @Test
    @DisplayName("The capability environment carries secrets but never prints them")
    void capabilityEnvironmentIsRedacted() {
        Map<String, String> environment = env();
        IdentityConfig c = IdentityConfig.load(environment);

        assertThat(c.capabilityEnvironment().asMap())
                .containsEntry("EXERIS_MFA_TOTP_PEPPER", environment.get("EXERIS_MFA_TOTP_PEPPER"))
                .containsEntry("EXERIS_TOKEN_ISSUER_ISSUER", ISSUER);
        assertThat(c.toString()).doesNotContain(environment.get("EXERIS_MFA_TOTP_PEPPER"))
                .doesNotContain(environment.get("EXERIS_TOKEN_ISSUER_KEKS"));
        assertThat(c.capabilityEnvironment().asMap()).doesNotContainKey("EXERIS_HTTP_PORT");
    }

    @Test
    @DisplayName("A verifier issuer or audience that differs from the issuer's is refused; an equal one is accepted")
    void verifierMatchesIssuer() {
        assertThat(IdentityConfig.load(env("EXERIS_JWT_ISSUER", ISSUER, "EXERIS_JWT_AUDIENCE", AUDIENCE))
                .jwt().issuer()).isEqualTo(ISSUER);
        assertThatThrownBy(() -> IdentityConfig.load(env("EXERIS_JWT_ISSUER", "https://other.example.test")))
                .isInstanceOf(IdentityConfigException.class)
                .hasMessageContaining("EXERIS_JWT_ISSUER must equal EXERIS_TOKEN_ISSUER_ISSUER");
        assertThatThrownBy(() -> IdentityConfig.load(env("EXERIS_JWT_AUDIENCE", "other")))
                .isInstanceOf(IdentityConfigException.class)
                .hasMessageContaining("EXERIS_JWT_AUDIENCE must equal EXERIS_TOKEN_ISSUER_AUDIENCE");
    }

    @Test
    @DisplayName("jwtProperties is accepted by the JWT capability and carries the issuer's issuer and audience")
    void jwtPropertiesAreUsable() {
        IdentityConfig c = IdentityConfig.load(env("EXERIS_JWT_CLOCK_SKEW_SECONDS", "45"));

        assertThat(c.jwtProperties())
                .containsEntry(JwtAdmissionPolicies.KEY_ISSUER, ISSUER)
                .containsEntry(JwtAdmissionPolicies.KEY_AUDIENCE, AUDIENCE)
                .containsEntry(JwtAdmissionPolicies.KEY_CLOCK_SKEW_SECONDS, "45")
                .doesNotContainKey(JwtAdmissionPolicies.KEY_JWKS_URI);
        assertThat(JwtAdmissionPolicies.fromProperties(c.jwtProperties(), () -> "{\"keys\":[]}")).isNotNull();
    }

    @Test
    @DisplayName("Token lifetimes are validated by the issuer capability and named by their setting")
    void tokenIssuerLifetimes() {
        IdentityConfig c = IdentityConfig.load(env("EXERIS_TOKEN_ISSUER_TOKEN_TTL", "PT10M"));
        assertThat(c.tokenIssuer().defaultTokenTtl()).isEqualTo(Duration.ofMinutes(10));

        assertThatThrownBy(() -> IdentityConfig.load(env("EXERIS_TOKEN_ISSUER_TOKEN_TTL", "PT2H")))
                .isInstanceOf(IdentityConfigException.class)
                .hasMessageContaining("EXERIS_TOKEN_ISSUER_TOKEN_TTL");
        assertThatThrownBy(() -> IdentityConfig.load(env("EXERIS_TOKEN_ISSUER_KEY_TTL", "soon")))
                .isInstanceOf(IdentityConfigException.class)
                .hasMessageContaining("EXERIS_TOKEN_ISSUER_KEY_TTL");
    }

    @Test
    @DisplayName("The second-factor challenge lifetime is a positive duration that fits its maximum")
    void mfaChallengeLifetimes() {
        assertThat(IdentityConfig.load(env("EXERIS_MFA_TOTP_CHALLENGE_TTL", "PT2M")).mfa().challengeTtl())
                .isEqualTo(Duration.ofMinutes(2));
        assertThatThrownBy(() -> IdentityConfig.load(env("EXERIS_MFA_TOTP_CHALLENGE_TTL", "PT20M")))
                .isInstanceOf(IdentityConfigException.class)
                .hasMessageContaining("EXERIS_MFA_TOTP_CHALLENGE_MAX_TTL");
        assertThatThrownBy(() -> IdentityConfig.load(env("EXERIS_MFA_TOTP_CHALLENGE_TTL", "-PT1M")))
                .isInstanceOf(IdentityConfigException.class)
                .hasMessageContaining("EXERIS_MFA_TOTP_CHALLENGE_TTL");
    }

    @Test
    @DisplayName("Rate limiting covers every public credential route, honours no forwarding header by default, and is accepted by the capability")
    void rateLimit() {
        IdentityConfig c = IdentityConfig.load(env(
                "EXERIS_RATELIMIT_LOGIN_CAPACITY", "7",
                "EXERIS_RATELIMIT_PASSWORD_RESET_REFILL_SECONDS", "120",
                "EXERIS_RATELIMIT_TRUSTED_PROXIES", "10.0.0.0/8"));

        IdentityConfig.Group login = c.rateLimit().groups().stream()
                .filter(g -> g.name().equals("login")).findFirst().orElseThrow();
        assertThat(login.capacity()).isEqualTo(7);
        assertThat(login.routes()).containsExactly("POST /api/v1/auth/login", "POST /api/v1/auth/mfa/verify");
        assertThat(c.rateLimit().groups()).filteredOn(g -> g.name().equals("password-reset"))
                .singleElement().satisfies(g -> assertThat(g.refillSeconds()).isEqualTo(120));
        assertThat(c.rateLimit().trustedProxies()).containsExactly("10.0.0.0/8");
        assertThat(c.rateLimit().groups()).flatExtracting(IdentityConfig.Group::routes)
                .contains("POST /api/v1/auth/refresh", "POST /api/v1/auth/password/reset-request",
                        "POST /api/v1/auth/verification/send", "POST /api/v1/auth/invitations/accept")
                .doesNotHaveDuplicates();
        assertThat(RateLimitFilterSettings.fromProperties(c.rateLimitProperties()).groups()).hasSize(5);
    }

    @Test
    @DisplayName("Rate-limit values the capability refuses are refused at load")
    void rateLimitRefusals() {
        assertThatThrownBy(() -> IdentityConfig.load(env("EXERIS_RATELIMIT_LOGIN_CAPACITY", "0")))
                .isInstanceOf(IdentityConfigException.class)
                .hasMessageContaining("EXERIS_RATELIMIT_LOGIN_CAPACITY");
        assertThatThrownBy(() -> IdentityConfig.load(env("EXERIS_RATELIMIT_FORWARDED_HEADER", "x-real-ip")))
                .isInstanceOf(IdentityConfigException.class)
                .hasMessageContaining("EXERIS_RATELIMIT_FORWARDED_HEADER");
    }

    @Test
    @DisplayName("CORS origins are plain origins; a wildcard, a path or another scheme is refused")
    void corsOrigins() {
        assertThat(IdentityConfig.load(env("EXERIS_CORS_ALLOWED_ORIGINS",
                "https://app.example.test, http://localhost:3000")).corsOrigins())
                .containsExactly("https://app.example.test", "http://localhost:3000");
        for (String bad : new String[] {"*", "https://app.example.test/path", "ftp://app.example.test",
                "app.example.test", "https://user@app.example.test"}) {
            assertThatThrownBy(() -> IdentityConfig.load(env("EXERIS_CORS_ALLOWED_ORIGINS", bad)))
                    .as(bad)
                    .isInstanceOf(IdentityConfigException.class)
                    .hasMessageContaining("EXERIS_CORS_ALLOWED_ORIGINS");
        }
    }

    @Test
    @DisplayName("Credential policies are read from their settings and cross-checked by the policy records")
    void credentialPolicies() {
        IdentityConfig c = IdentityConfig.load(env(
                "EXERIS_CREDENTIALS_LOCKOUT_MAX_ATTEMPTS", "3",
                "EXERIS_CREDENTIALS_LOCKOUT_DURATION_SECONDS", "600",
                "EXERIS_CREDENTIALS_TOKEN_RESET_VALIDITY_SECONDS", "300",
                "EXERIS_CREDENTIALS_PASSWORD_MIN_LENGTH", "12"));

        assertThat(c.credentials().lockout().maxAttempts()).isEqualTo(3);
        assertThat(c.credentials().lockout().lockoutDuration()).isEqualTo(Duration.ofSeconds(600));
        assertThat(c.credentials().token().resetValidity()).isEqualTo(Duration.ofSeconds(300));
        assertThat(c.credentials().password().minLength()).isEqualTo(12);

        assertThatThrownBy(() -> IdentityConfig.load(env(
                "EXERIS_CREDENTIALS_PASSWORD_MIN_LENGTH", "100", "EXERIS_CREDENTIALS_PASSWORD_MAX_LENGTH", "50")))
                .isInstanceOf(IdentityConfigException.class)
                .hasMessageContaining("EXERIS_CREDENTIALS_PASSWORD_MIN_LENGTH");
        assertThatThrownBy(() -> IdentityConfig.load(env("EXERIS_CREDENTIALS_LOCKOUT_MAX_ATTEMPTS", "many")))
                .isInstanceOf(IdentityConfigException.class)
                .hasMessageContaining("EXERIS_CREDENTIALS_LOCKOUT_MAX_ATTEMPTS");
    }

    @Test
    @DisplayName("Argon2id parameters below the floor are refused, naming the setting")
    void passwordHashingFloor() {
        assertThat(IdentityConfig.load(env("EXERIS_PASSWORD_ARGON2_MEMORY_KIB", "19456",
                "EXERIS_PASSWORD_ARGON2_ITERATIONS", "2")).passwordHashing().iterations()).isEqualTo(2);
        assertThatThrownBy(() -> IdentityConfig.load(env("EXERIS_PASSWORD_ARGON2_MEMORY_KIB", "1024")))
                .isInstanceOf(IdentityConfigException.class)
                .hasMessageContaining("EXERIS_PASSWORD_ARGON2_MEMORY_KIB");
    }

    @Test
    @DisplayName("A properties file supplies settings, the environment overrides it, an unknown key is refused")
    void fileAndEnvironment(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("identity.properties");
        Files.writeString(file, "EXERIS_HTTP_PORT=9000\nEXERIS_HTTP_BIND_HOST=0.0.0.0\n");
        Map<String, String> base = env("EXERIS_IDENTITY_CONFIG", file.toString());

        IdentityConfig fromFile = IdentityConfig.load(base);
        assertThat(fromFile.http().port()).isEqualTo(9000);
        assertThat(fromFile.http().bindHost()).isEqualTo("0.0.0.0");

        Map<String, String> overridden = new HashMap<>(base);
        overridden.put("EXERIS_HTTP_PORT", "9100");
        assertThat(IdentityConfig.load(overridden).http().port()).isEqualTo(9100);

        Files.writeString(file, "EXERIS_HTTP_PORT=9000\nEXERIS_DEV_SIGNING_KEY=anything\n");
        assertThatThrownBy(() -> IdentityConfig.load(base))
                .isInstanceOf(IdentityConfigException.class)
                .hasMessageContaining("unknown setting: EXERIS_DEV_SIGNING_KEY");

        Map<String, String> missing = env("EXERIS_IDENTITY_CONFIG", dir.resolve("absent").toString());
        assertThatThrownBy(() -> IdentityConfig.load(missing))
                .isInstanceOf(IdentityConfigException.class)
                .hasMessageContaining("EXERIS_IDENTITY_CONFIG");
    }

    @Test
    @DisplayName("Numeric settings must be whole numbers inside their bounds")
    void numericBounds() {
        for (String port : new String[] {"0", "65536", "http"}) {
            assertThatThrownBy(() -> IdentityConfig.load(env("EXERIS_HTTP_PORT", port)))
                    .as(port)
                    .isInstanceOf(IdentityConfigException.class)
                    .hasMessageContaining("EXERIS_HTTP_PORT");
        }
        assertThatThrownBy(() -> IdentityConfig.load(env("EXERIS_HTTP_MAX_REQUEST_BODY_BYTES", "0")))
                .isInstanceOf(IdentityConfigException.class)
                .hasMessageContaining("EXERIS_HTTP_MAX_REQUEST_BODY_BYTES");
    }
}
