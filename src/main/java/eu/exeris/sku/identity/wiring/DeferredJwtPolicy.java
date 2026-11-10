package eu.exeris.sku.identity.wiring;

import eu.exeris.caps.jwt.api.JwtAdmissionPolicy;
import eu.exeris.caps.jwt.api.JwtValidationResult;
import eu.exeris.caps.jwt.api.JwtValidationStatus;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A token policy whose key source is bound once the signing keys exist.
 *
 * <p>The verifier loads the issuer's key set when it is built and keeps it until the next scheduled
 * refresh, so a verifier built before the issuer has created its first signing key would refuse every token
 * until then. This policy is attached to the admission chain at once and refuses every token until
 * {@link #bind} supplies the real policy.
 */
public final class DeferredJwtPolicy implements JwtAdmissionPolicy, AutoCloseable {

    private final AtomicReference<JwtAdmissionPolicy> delegate = new AtomicReference<>();

    @Override
    public JwtValidationResult validate(CharSequence authorizationHeader) {
        JwtAdmissionPolicy bound = delegate.get();
        return bound != null ? bound.validate(authorizationHeader) : notReady();
    }

    @Override
    public JwtValidationResult validateToken(CharSequence rawToken) {
        JwtAdmissionPolicy bound = delegate.get();
        return bound != null ? bound.validateToken(rawToken) : notReady();
    }

    /**
     * Supplies the policy that does the checking.
     *
     * @param policy the real policy; closed with this one if it is {@link AutoCloseable}
     */
    public void bind(JwtAdmissionPolicy policy) {
        if (!delegate.compareAndSet(null, Objects.requireNonNull(policy, "policy must not be null"))) {
            throw new IllegalStateException("the policy is already bound");
        }
    }

    @Override
    public void close() throws Exception {
        JwtAdmissionPolicy bound = delegate.getAndSet(null);
        if (bound instanceof AutoCloseable closeable) {
            closeable.close();
        }
    }

    private static JwtValidationResult notReady() {
        return JwtValidationResult.failure(JwtValidationStatus.UNKNOWN_KEY, "token verification is not ready");
    }
}
