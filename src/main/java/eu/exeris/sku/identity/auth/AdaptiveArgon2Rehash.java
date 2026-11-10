package eu.exeris.sku.identity.auth;

import eu.exeris.caps.credentialstore.api.RehashablePasswordEncoder;
import eu.exeris.kernel.spi.security.credentials.KernelPasswordEncoder;
import eu.exeris.kernel.spi.security.credentials.PasswordEncoderConfig;

import java.util.Base64;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Makes a {@link KernelPasswordEncoder} report when a stored hash was made with other parameters than
 * the configured ones, so the credential store re-hashes it at the next successful login.
 *
 * <p>Only Argon2id hashes in PHC form are accepted. A hash in any other form never matches and always
 * needs a re-hash, so a stale or foreign hash cannot authenticate and cannot make a login fail with an
 * exception.
 */
public final class AdaptiveArgon2Rehash implements KernelPasswordEncoder, RehashablePasswordEncoder {

    private static final Pattern PHC = Pattern.compile(
            "\\$argon2id\\$v=19\\$m=(\\d{1,10}),t=(\\d{1,10}),p=(\\d{1,10})\\$[A-Za-z0-9+/]+\\$([A-Za-z0-9+/]+)");

    private final KernelPasswordEncoder delegate;
    private final PasswordEncoderConfig target;

    /**
     * @param delegate the Argon2id encoder hashes are made and checked with
     * @param target   the parameters new hashes are made with, which {@link #needsRehash} compares against
     */
    public AdaptiveArgon2Rehash(KernelPasswordEncoder delegate, PasswordEncoderConfig target) {
        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
        this.target = Objects.requireNonNull(target, "target must not be null");
    }

    @Override
    public String encode(char[] raw) {
        return delegate.encode(raw);
    }

    @Override
    public boolean matches(char[] raw, String encoded) {
        if (raw == null || raw.length == 0 || encoded == null || !PHC.matcher(encoded).matches()) {
            return false;
        }
        try {
            return delegate.matches(raw, encoded);
        } catch (IllegalArgumentException malformed) {
            return false;
        }
    }

    @Override
    public boolean needsRehash(String encoded) {
        if (encoded == null) {
            return true;
        }
        Matcher m = PHC.matcher(encoded);
        if (!m.matches()) {
            return true;
        }
        try {
            long memory = Long.parseLong(m.group(1));
            long iterations = Long.parseLong(m.group(2));
            long parallelism = Long.parseLong(m.group(3));
            int hashLength = Base64.getDecoder().decode(padded(m.group(4))).length;
            return memory != target.memoryCostKib()
                    || iterations != target.iterations()
                    || parallelism != target.parallelism()
                    || hashLength != target.hashLength();
        } catch (IllegalArgumentException malformed) {
            return true;
        }
    }

    private static String padded(String unpadded) {
        int missing = (4 - unpadded.length() % 4) % 4;
        return unpadded + "=".repeat(missing);
    }
}
