package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.config.IdentityConfig;
import eu.exeris.sku.identity.config.IdentityConfigException;
import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.TestConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The keyrings and the pepper are not among the secrets the launcher is told, so a refusal must never
 * quote them. Each setting is given a value that is invalid in each way its validator checks, and the output
 * of a launcher started with it must hold no part of it.
 */
@Tag("kernel-boot")
@DisplayName("Key material: an invalid keyring or pepper is never quoted")
class KeyMaterialSecretsIT {

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final List<String> KEYRINGS = List.of("EXERIS_TOKEN_ISSUER_KEKS", "EXERIS_MFA_TOTP_KEKS",
            "EXERIS_FEDERATED_LOGIN_STATE_KEYS");

    /** The base64 text of random bytes: the secret material of a key. */
    private static String key(int bytes) {
        byte[] raw = new byte[bytes];
        RANDOM.nextBytes(raw);
        return Base64.getEncoder().encodeToString(raw);
    }

    /** What one invalid value is, and the secret material in it that must not appear. */
    private record Invalid(String how, String value, List<String> material) {
    }

    private static List<Invalid> invalidKeyrings() {
        List<Invalid> all = new ArrayList<>();
        String shortKey = key(16);
        all.add(new Invalid("wrong length", "k1:" + shortKey, List.of(shortKey)));
        String longKey = key(48);
        all.add(new Invalid("wrong length, long", "k1:" + longKey, List.of(longKey)));
        String notBase64 = SecretForms.marker(40) + "!*";
        all.add(new Invalid("not Base64", "k1:" + notBase64, List.of(notBase64)));
        String one = key(32);
        String two = key(32);
        all.add(new Invalid("duplicate id", "k1:" + one + ",k1:" + two, List.of(one, two)));
        String bare = key(32);
        all.add(new Invalid("entry without an id", bare, List.of(bare)));
        String reversed = SecretForms.marker(24);
        all.add(new Invalid("id and key reversed", reversed + ":k1", List.of(reversed)));
        String spaced = key(32);
        all.add(new Invalid("id with a space", "k 1:" + spaced, List.of(spaced)));
        return all;
    }

    private static List<Invalid> invalidPeppers() {
        List<Invalid> all = new ArrayList<>();
        String shortPepper = key(16);
        all.add(new Invalid("too short", shortPepper, List.of(shortPepper)));
        String notBase64 = SecretForms.marker(40) + "!*";
        all.add(new Invalid("not Base64", notBase64, List.of(notBase64)));
        String text = SecretForms.markerWithSpecials();
        all.add(new Invalid("text with specials", text, List.of(text)));
        return all;
    }

    private record Outcome(int status, String output, boolean served) {
    }

    /** Starts the launcher and returns when it exits or serves; a serving one is stopped. */
    private static Outcome launch(Map<String, String> env) throws Exception {
        try (LaunchedProcess process = LaunchedProcess.start(env)) {
            long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(120);
            while (process.isAlive() && System.nanoTime() < deadline
                    && !process.output().contains(ServeSupport.RUNNING_LINE)) {
                Thread.sleep(50);
            }
            boolean served = process.output().contains(ServeSupport.RUNNING_LINE);
            int status = served ? process.terminate(60) : ServeSupport.awaitExitOrDestroy(process, 10);
            return new Outcome(status, process.output(), served);
        }
    }

    private static Map<String, String> environment(PostgresSupport.Database database) {
        Map<String, String> env = ServeSupport.licensedEnvironment(database, freePort(),
                InMemoryMembershipDirectory.class.getName());
        env.put("EXERIS_TOKEN_ISSUER_MANUAL_ROTATION", "true");
        return env;
    }

    private static int freePort() {
        try {
            return LaunchedProcess.freePort();
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private record Case(String setting, Invalid invalid, boolean inFile) {
        String name() {
            return setting + " " + invalid.how() + (inFile ? " (from the configuration file)" : "");
        }
    }

    @Test
    @DisplayName("Each keyring and the pepper, invalid in each way, is refused or accepted without a part of it, a prefix or a suffix of six characters, reaching the output")
    void invalidKeyMaterialIsNeverQuoted(@TempDir Path dir) throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        List<Case> cases = new ArrayList<>();
        for (String keyring : KEYRINGS) {
            for (Invalid invalid : invalidKeyrings()) {
                cases.add(new Case(keyring, invalid, false));
            }
            cases.add(new Case(keyring, invalidKeyrings().getFirst(), true));
        }
        for (Invalid invalid : invalidPeppers()) {
            cases.add(new Case("EXERIS_MFA_TOTP_PEPPER", invalid, false));
        }
        cases.add(new Case("EXERIS_MFA_TOTP_PEPPER", invalidPeppers().getFirst(), true));

        Map<Case, Future<Outcome>> running = new LinkedHashMap<>();
        try (ExecutorService pool = Executors.newFixedThreadPool(4)) {
            int n = 0;
            for (Case c : cases) {
                Map<String, String> env = environment(database);
                if (c.inFile()) {
                    env.remove(c.setting());
                    Path file = Files.writeString(dir.resolve("identity-" + n++ + ".properties"),
                            c.setting() + "=" + c.invalid().value().replace("\\", "\\\\") + "\n");
                    env.put("EXERIS_IDENTITY_CONFIG", file.toString());
                } else {
                    env.put(c.setting(), c.invalid().value());
                }
                running.put(c, pool.submit(() -> launch(env)));
            }
            List<String> problems = new ArrayList<>();
            for (Map.Entry<Case, Future<Outcome>> entry : running.entrySet()) {
                Outcome outcome = entry.getValue().get();
                if (outcome.status() != IdentitySkuApplication.EXIT_NOT_COMPLETED
                        || !outcome.output().contains("Identity failed while starting")
                        || !outcome.output().contains("ConfigurationException")) {
                    problems.add(entry.getKey().name() + ": the invalid value was not refused as a configuration exception "
                            + "(status " + outcome.status() + ", served " + outcome.served() + ")");
                }
                for (String material : entry.getKey().invalid().material()) {
                    List<String> found = new ArrayList<>(SecretForms.leaks(outcome.output(), "KEY", material));
                    for (String piece : List.of(material.substring(0, 6), material.substring(material.length() - 6))) {
                        if (outcome.output().contains(piece)) {
                            found.add("a six-character piece of the key material appears");
                        }
                    }
                    if (!found.isEmpty()) {
                        problems.add(entry.getKey().name() + " (status " + outcome.status() + "): " + found);
                    }
                }
            }
            assertThat(problems).as("key material in the output, or a value that was not refused").isEmpty();
        }
    }

    @Test
    @DisplayName("The configuration loader itself, given each invalid value, either loads or refuses without quoting it")
    void loaderDoesNotQuote() {
        List<String> leaks = new ArrayList<>();
        for (String setting : List.of("EXERIS_TOKEN_ISSUER_KEKS", "EXERIS_MFA_TOTP_KEKS",
                "EXERIS_FEDERATED_LOGIN_STATE_KEYS", "EXERIS_MFA_TOTP_PEPPER")) {
            for (Invalid invalid : setting.endsWith("PEPPER") ? invalidPeppers() : invalidKeyrings()) {
                Map<String, String> env = TestConfig.env();
                env.put(setting, invalid.value());
                try {
                    IdentityConfig.load(env);
                } catch (IdentityConfigException refused) {
                    for (String material : invalid.material()) {
                        leaks.addAll(SecretForms.leaks(refused.getMessage(), "KEY", material));
                    }
                }
            }
        }
        assertThat(leaks).isEmpty();
    }
}
