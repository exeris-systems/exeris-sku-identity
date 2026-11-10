package eu.exeris.sku.identity.auth;

import eu.exeris.kernel.community.security.Argon2idPasswordEncoder;
import eu.exeris.kernel.spi.security.credentials.PasswordEncoderConfig;
import eu.exeris.sku.identity.support.TestConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("AdaptiveArgon2Rehash")
class AdaptiveArgon2RehashTest {

    private static final PasswordEncoderConfig CURRENT = new PasswordEncoderConfig(8_192, 2, 1, 32);

    private static AdaptiveArgon2Rehash encoderFor(PasswordEncoderConfig config) {
        return new AdaptiveArgon2Rehash(new Argon2idPasswordEncoder(config), CURRENT);
    }

    @Test
    @DisplayName("a hash made with the configured parameters does not need a re-hash and still matches")
    void currentHashIsKept() {
        AdaptiveArgon2Rehash encoder = encoderFor(CURRENT);
        char[] password = TestConfig.randomPassword();

        String hash = encoder.encode(password);

        assertThat(encoder.needsRehash(hash)).isFalse();
        assertThat(encoder.matches(password, hash)).isTrue();
        assertThat(encoder.matches(TestConfig.randomPassword(), hash)).isFalse();
    }

    @Test
    @DisplayName("a hash whose memory, iterations, parallelism or length differ needs a re-hash")
    void changedParametersNeedRehash() {
        char[] password = TestConfig.randomPassword();

        for (PasswordEncoderConfig old : new PasswordEncoderConfig[] {
                new PasswordEncoderConfig(16_384, 2, 1, 32),
                new PasswordEncoderConfig(8_192, 3, 1, 32),
                new PasswordEncoderConfig(8_192, 2, 2, 32),
                new PasswordEncoderConfig(8_192, 2, 1, 24)}) {
            AdaptiveArgon2Rehash legacy = encoderFor(old);
            String hash = legacy.encode(password);

            assertThat(encoderFor(CURRENT).needsRehash(hash)).as(old.toString()).isTrue();
            assertThat(encoderFor(CURRENT).matches(password, hash)).as(old.toString()).isTrue();
        }
    }

    @Test
    @DisplayName("a hash in another form needs a re-hash and never matches or throws")
    void foreignHashIsRefused() {
        AdaptiveArgon2Rehash encoder = encoderFor(CURRENT);
        char[] password = TestConfig.randomPassword();
        String foreign = "$2b$12$" + TestConfig.randomBase64(24).replace("=", "");
        String truncated = "$argon2id$v=19$m=8192,t=2,p=1$" + TestConfig.randomBase64(12).replace("=", "");

        for (String stored : new String[] {foreign, truncated, "", "plain"}) {
            assertThat(encoder.needsRehash(stored)).as(stored).isTrue();
            assertThat(encoder.matches(password, stored)).as(stored).isFalse();
        }
        assertThat(encoder.needsRehash(null)).isTrue();
        assertThat(encoder.matches(password, null)).isFalse();
        assertThat(encoder.matches(new char[0], encoder.encode(password))).isFalse();
    }
}
