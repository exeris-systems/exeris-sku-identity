package eu.exeris.sku.identity.launcher;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static eu.exeris.sku.identity.launcher.BootstrapOwnerSupport.EMAIL;
import static eu.exeris.sku.identity.launcher.BootstrapOwnerSupport.INLINE_PASSWORD;
import static eu.exeris.sku.identity.launcher.BootstrapOwnerSupport.PASSWORD_FILE;
import static eu.exeris.sku.identity.launcher.BootstrapOwnerSupport.TENANT;
import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Settings of the bootstrap-owner command")
class BootstrapOwnerSettingsTest {

    private static Map<String, String> complete() {
        Map<String, String> env = new HashMap<>();
        env.put(EMAIL, "owner@example.test");
        env.put(PASSWORD_FILE, "/run/secrets/owner");
        return env;
    }

    private static String problems(LauncherEnvironment in) {
        return String.join("\n", in.problems());
    }

    @Test
    @DisplayName("Without a directory, e-mail and file are enough and the tenant is absent")
    void noDirectory() {
        LauncherEnvironment in = new LauncherEnvironment(complete());

        BootstrapOwnerSettings settings = BootstrapOwnerSettings.read(in, false);

        assertThat(in.problems()).isEmpty();
        assertThat(settings.email()).isEqualTo("owner@example.test");
        assertThat(settings.passwordFile()).isEqualTo(Path.of("/run/secrets/owner"));
        assertThat(settings.tenantId()).isNull();
    }

    @Test
    @DisplayName("With a directory the tenant is required and read as a UUID")
    void withDirectory() {
        UUID tenant = UUID.randomUUID();
        Map<String, String> env = complete();
        env.put(TENANT, tenant.toString());
        LauncherEnvironment in = new LauncherEnvironment(env);

        BootstrapOwnerSettings settings = BootstrapOwnerSettings.read(in, true);

        assertThat(in.problems()).isEmpty();
        assertThat(settings.tenantId()).isEqualTo(tenant);
    }

    @Test
    @DisplayName("Every problem is reported in one pass, each naming its key")
    void allProblemsAtOnce() {
        Map<String, String> env = new HashMap<>();
        env.put(INLINE_PASSWORD, "inline-" + UUID.randomUUID());
        env.put(TENANT, "not-a-uuid");
        LauncherEnvironment in = new LauncherEnvironment(env);

        assertThat(BootstrapOwnerSettings.read(in, true)).isNull();

        assertThat(problems(in)).contains(EMAIL, PASSWORD_FILE, INLINE_PASSWORD, TENANT);
        assertThat(problems(in)).doesNotContain(env.get(INLINE_PASSWORD));
    }

    @Test
    @DisplayName("The inline password variable is refused whenever it is set, and its value is never echoed")
    void inlinePasswordIsRefused() {
        Map<String, String> env = complete();
        String value = "inline-" + UUID.randomUUID();
        env.put(INLINE_PASSWORD, value);
        LauncherEnvironment in = new LauncherEnvironment(env);

        assertThat(BootstrapOwnerSettings.read(in, false)).isNull();

        assertThat(problems(in)).contains(INLINE_PASSWORD).doesNotContain(value);
    }

    @Test
    @DisplayName("A directory without a tenant, and a tenant that is not a UUID, are refused")
    void tenantRules() {
        LauncherEnvironment missing = new LauncherEnvironment(complete());
        assertThat(BootstrapOwnerSettings.read(missing, true)).isNull();
        assertThat(problems(missing)).contains(TENANT);

        Map<String, String> env = complete();
        env.put(TENANT, "123");
        LauncherEnvironment malformed = new LauncherEnvironment(env);
        assertThat(BootstrapOwnerSettings.read(malformed, true)).isNull();
        assertThat(problems(malformed)).contains(TENANT);
    }

    @Test
    @DisplayName("A tenant without a directory is refused")
    void tenantWithoutDirectory() {
        Map<String, String> env = complete();
        env.put(TENANT, UUID.randomUUID().toString());
        LauncherEnvironment in = new LauncherEnvironment(env);

        assertThat(BootstrapOwnerSettings.read(in, false)).isNull();
        assertThat(problems(in)).contains(TENANT);
    }

    @Test
    @DisplayName("An address longer than 320 characters is refused; 320 is not")
    void addressLength() {
        Map<String, String> env = complete();
        env.put(EMAIL, "a".repeat(321));
        LauncherEnvironment tooLong = new LauncherEnvironment(env);
        assertThat(BootstrapOwnerSettings.read(tooLong, false)).isNull();
        assertThat(problems(tooLong)).contains(EMAIL);

        env.put(EMAIL, "a".repeat(320));
        LauncherEnvironment edge = new LauncherEnvironment(env);
        assertThat(BootstrapOwnerSettings.read(edge, false)).isNotNull();
        assertThat(edge.problems()).isEmpty();
    }

    @Test
    @DisplayName("The text form carries the path and no secret")
    void textForm() {
        LauncherEnvironment in = new LauncherEnvironment(complete());

        assertThat(BootstrapOwnerSettings.read(in, false).toString()).contains("/run/secrets/owner");
    }
}
