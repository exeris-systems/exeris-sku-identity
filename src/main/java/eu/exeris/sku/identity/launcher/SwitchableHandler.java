package eu.exeris.sku.identity.launcher;

import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpHandler;
import eu.exeris.kernel.spi.http.HttpResponse;
import eu.exeris.kernel.spi.http.HttpStatus;

import java.util.concurrent.atomic.AtomicReference;

/**
 * The handler the kernel's HTTP server is started with. The server binds its port while the kernel boots,
 * before the services that answer requests exist, so requests get 503 until a handler is set and again
 * once it is withdrawn at shutdown.
 */
final class SwitchableHandler implements HttpHandler {

    private final AtomicReference<HttpHandler> target = new AtomicReference<>();

    void serve(HttpHandler handler) {
        target.set(handler);
    }

    void withdraw() {
        target.set(null);
    }

    @Override
    public void handle(HttpExchange exchange) {
        HttpHandler handler = target.get();
        if (handler == null) {
            exchange.respond(HttpResponse.noBody(HttpStatus.SERVICE_UNAVAILABLE, exchange.request().version()));
            return;
        }
        handler.handle(exchange);
    }
}
