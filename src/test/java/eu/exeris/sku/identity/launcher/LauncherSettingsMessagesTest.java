package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.config.IdentityConfigException;
import eu.exeris.sku.identity.support.TestConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The launcher's own settings are refused by setting name and bound, never by the value the operator gave:
 * the declared environment, the database URL, the pool size, the host-part class names and the bootstrap-owner
 * settings.
 */
@DisplayName("Launcher settings: a refusal names the setting, never the value")
class LauncherSettingsMessagesTest {

    private static Map<String, String> env(String... kv) {
        Map<String, String> env = new HashMap<>(TestConfig.env());
        env.put("EXERIS_ENVIRONMENT", "development");
        env.put("EXERIS_DATABASE_URL", "jdbc:postgresql://127.0.0.1:5432/identity");
        env.put("EXERIS_DATABASE_USER", "identity_service");
        env.put("EXERIS_DATABASE_PASSWORD", "unused-in-this-test");
        for (int i = 0; i < kv.length; i += 2) {
            env.put(kv[i], kv[i + 1]);
        }
        return env;
    }

    private static String refusal(Map<String, String> environment) {
        Throwable[] caught = new Throwable[1];
        assertThatThrownBy(() -> {
            try {
                StartupPlan.prepare(environment);
            } catch (IdentityConfigException e) {
                caught[0] = e;
                throw e;
            }
        }).isInstanceOf(IdentityConfigException.class);
        return String.join("\n", ((IdentityConfigException) caught[0]).problems());
    }

    private static void assertNoPieceOf(String text, String marker) {
        assertThat(text).doesNotContain(marker);
        for (int i = 0; i + 6 <= marker.length(); i++) {
            assertThat(text).doesNotContain(marker.substring(i, i + 6));
        }
    }

    @Test
    @DisplayName("An unknown environment, a URL of another scheme, a pool size out of range or not a number are refused by setting")
    void scalarSettings() {
        for (String value : List.of(SecretForms.marker(), SecretForms.numericMarker())) {
            String text = refusal(env("EXERIS_ENVIRONMENT", value));
            assertThat(text).contains("EXERIS_ENVIRONMENT names an environment that does not exist");
            assertNoPieceOf(text, value);

            text = refusal(env("EXERIS_DATABASE_MAX_POOL_SIZE", value));
            assertThat(text).containsPattern("EXERIS_DATABASE_MAX_POOL_SIZE must be (between 1 and 1000|a whole number)");
            assertNoPieceOf(text, value);
        }
        String marker = SecretForms.marker();
        String text = refusal(env("EXERIS_DATABASE_URL", "postgresql://identity_service:" + marker + "@db.example.test/identity"));
        assertThat(text).contains("EXERIS_DATABASE_URL must be a jdbc:postgresql: URL.");
        assertNoPieceOf(text, marker);
    }

    @Test
    @DisplayName("A host-part class that does not exist, or is not of the type, is refused by setting")
    void hostParts() {
        String marker = SecretForms.marker();
        for (String key : List.of("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY", "EXERIS_IDENTITY_NOTIFICATION_DISPATCHER",
                "EXERIS_IDENTITY_INVITATION_DELIVERY")) {
            for (String value : List.of("com.example." + marker, "java.lang.String", marker)) {
                String text = refusal(env(key, value));

                assertThat(text).contains(key + " names a class that ");
                assertNoPieceOf(text, marker);
            }
        }
    }

    @Test
    @DisplayName("The bootstrap-owner settings are refused by setting: a tenant that is not a UUID, a path that is invalid, an address too long")
    void bootstrapOwnerSettings() {
        String marker = SecretForms.marker();
        LauncherEnvironment in = new LauncherEnvironment(Map.of(
                BootstrapOwnerSettings.EMAIL, marker + "@" + "a".repeat(400) + ".example",
                BootstrapOwnerSettings.PASSWORD_FILE, "bad\u0000" + marker,
                BootstrapOwnerSettings.TENANT, marker,
                BootstrapOwnerSettings.INLINE_PASSWORD, marker));

        BootstrapOwnerSettings settings = BootstrapOwnerSettings.read(in, true);

        assertThat(settings).isNull();
        assertThat(in.problems()).hasSize(4);
        assertNoPieceOf(String.join("\n", in.problems()), marker);
    }
}
