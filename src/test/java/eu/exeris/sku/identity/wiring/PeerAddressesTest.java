package eu.exeris.sku.identity.wiring;

import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpHandler;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpRequest;
import eu.exeris.kernel.spi.http.HttpResponse;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.http.HttpVersion;
import eu.exeris.sku.identity.support.TestExchange;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("PeerAddresses")
class PeerAddressesTest {

    /** An exchange that, like the registry's decorator, reports no peer address. */
    private static final class Decorated implements HttpExchange {

        private final HttpRequest request = HttpRequest.noBody(HttpMethod.GET, "/", HttpVersion.HTTP_1_1, List.of());

        @Override
        public HttpRequest request() {
            return request;
        }

        @Override
        public void respond(HttpResponse response) {
        }

        @Override
        public void respond(HttpStatus status) {
        }
    }

    @Test
    @DisplayName("the address of the transport's exchange is visible to code that only sees a decorated one")
    void boundAddressSurvivesDecoration() {
        AtomicReference<Optional<String>> seen = new AtomicReference<>();
        HttpHandler downstream = exchange -> seen.set(PeerAddresses.source().peerAddress(new Decorated()));

        PeerAddresses.binding(downstream).handle(TestExchange.of(HttpMethod.GET, "/").from("198.51.100.99"));

        assertThat(seen.get()).contains("198.51.100.99");
    }

    @Test
    @DisplayName("outside a bound request the exchange's own address is used, and may be absent")
    void fallsBackToTheExchange() {
        assertThat(PeerAddresses.source().peerAddress(TestExchange.of(HttpMethod.GET, "/").from("198.51.100.5")))
                .contains("198.51.100.5");
        assertThat(PeerAddresses.source().peerAddress(new Decorated())).isEmpty();
    }

    @Test
    @DisplayName("the binding ends with the request")
    void bindingEnds() {
        PeerAddresses.binding(exchange -> { }).handle(TestExchange.of(HttpMethod.GET, "/").from("198.51.100.99"));

        assertThat(PeerAddresses.source().peerAddress(new Decorated())).isEmpty();
    }
}
