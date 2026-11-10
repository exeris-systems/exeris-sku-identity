package eu.exeris.sku.identity.support;

import eu.exeris.sku.identity.config.IdentityConfig;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/** A complete identity configuration whose key material is generated for each call. */
public final class TestConfig {

    /** The issuer the tests' tokens carry. */
    public static final String ISSUER = "urn:example:identity-test";
    /** The audience the tests' tokens carry. */
    public static final String AUDIENCE = "example-api";

    private static final SecureRandom RANDOM = new SecureRandom();

    private TestConfig() {
    }

    /** A valid environment with manual signing-key rotation, so no scheduler is needed. */
    public static Map<String, String> env() {
        Map<String, String> env = new HashMap<>();
        env.put("EXERIS_TOKEN_ISSUER_ISSUER", ISSUER);
        env.put("EXERIS_TOKEN_ISSUER_AUDIENCE", AUDIENCE);
        env.put("EXERIS_TOKEN_ISSUER_MANUAL_ROTATION", "true");
        env.put("EXERIS_TOKEN_ISSUER_KEKS", "k1:" + randomBase64(32));
        env.put("EXERIS_MFA_TOTP_KEKS", "k1:" + randomBase64(32));
        env.put("EXERIS_MFA_TOTP_PEPPER", randomBase64(32));
        env.put("EXERIS_FEDERATED_LOGIN_STATE_KEYS", "k1:" + randomBase64(32));
        return env;
    }

    /** The configuration loaded from {@link #env()}. */
    public static IdentityConfig load() {
        return IdentityConfig.load(env());
    }

    /** Random bytes, base64 encoded. */
    public static String randomBase64(int bytes) {
        byte[] raw = new byte[bytes];
        RANDOM.nextBytes(raw);
        return Base64.getEncoder().encodeToString(raw);
    }

    /** A random password that satisfies the default policy. */
    public static char[] randomPassword() {
        return ("Pw-" + randomBase64(18)).toCharArray();
    }
}
