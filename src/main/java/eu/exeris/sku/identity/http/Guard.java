package eu.exeris.sku.identity.http;

import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpHandler;
import eu.exeris.sku.identity.auth.PrincipalBridge;
import eu.exeris.sku.identity.auth.TenantScope;

/**
 * Wraps every route handler: the work runs with the persistence scope bound, and whatever it throws becomes
 * one of the fixed {@link Problem} responses. The text of an exception is logged, never sent.
 */
final class Guard {

    private static final System.Logger LOG = System.getLogger(Guard.class.getName());

    private final Responses responses;

    Guard(Responses responses) {
        this.responses = responses;
    }

    /** A handler of a route that admits a caller without a token; no tenant is bound. */
    HttpHandler anonymous(HttpHandler handler) {
        return exchange -> guarded(exchange, () -> TenantScope.run(null, () -> handler.handle(exchange)));
    }

    /** A handler of a route that needs a token; the principal and its tenant are bound for the handler. */
    HttpHandler authenticated(HttpHandler handler) {
        HttpHandler bridged = PrincipalBridge.authenticated(handler);
        return exchange -> guarded(exchange, () -> bridged.handle(exchange));
    }

    private void guarded(HttpExchange exchange, Runnable work) {
        try {
            if (exchange.request().path().indexOf('?') >= 0) {
                throw Problem.INVALID_REQUEST.raise();
            }
            work.run();
        } catch (Problem.Failure failure) {
            responses.problem(exchange, failure.problem());
        } catch (IllegalArgumentException e) {
            responses.problem(exchange, Problem.INVALID_REQUEST);
        } catch (RuntimeException e) {
            LOG.log(System.Logger.Level.ERROR, "request failed", e);
            responses.problem(exchange, Problem.INTERNAL_ERROR);
        }
    }
}
