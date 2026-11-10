package eu.exeris.sku.identity.wiring;

import eu.exeris.caps.ratelimit.api.PeerAddressSource;
import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpHandler;

import java.util.Objects;
import java.util.Optional;

/**
 * Carries the connection's peer address past the route registry, which hands its admission filters and its
 * handlers a decorated exchange that does not report one.
 *
 * <p>{@link #binding} wraps the handler the transport calls and binds the address of the real exchange for
 * the duration of the request; {@link #source()} reads it back, falling back to the exchange itself when
 * nothing is bound. Without the binding every client of the rate limit would share one bucket.
 */
public final class PeerAddresses {

    private static final ScopedValue<String> PEER = ScopedValue.newInstance();

    private PeerAddresses() {
    }

    /**
     * Wraps a handler so the peer address of each exchange is visible while it runs.
     *
     * @param delegate the handler the transport would call
     * @return a handler that binds the address and calls the delegate
     */
    public static HttpHandler binding(HttpHandler delegate) {
        Objects.requireNonNull(delegate, "delegate must not be null");
        return exchange -> {
            String address = exchange.remoteAddress();
            if (address == null) {
                delegate.handle(exchange);
            } else {
                ScopedValue.where(PEER, address).run(() -> delegate.handle(exchange));
            }
        };
    }

    /** The peer address as bound by {@link #binding}, or the exchange's own when none is bound. */
    public static PeerAddressSource source() {
        return PeerAddresses::current;
    }

    /**
     * The peer address of the request being handled.
     *
     * @param exchange the exchange, consulted when no address is bound
     * @return the address, or empty when the transport reports none
     */
    public static Optional<String> current(HttpExchange exchange) {
        if (PEER.isBound()) {
            return Optional.of(PEER.get());
        }
        return Optional.ofNullable(exchange.remoteAddress());
    }
}
