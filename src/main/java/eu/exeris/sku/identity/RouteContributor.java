package eu.exeris.sku.identity;

import eu.exeris.caps.serviceboundarycore.api.ApiSurfaceRoute;

import java.util.List;
import java.util.Set;

/**
 * Supplies routes to register on the composition's strict registry before it freezes.
 *
 * <p>A route that admits a request without a token is declared {@code permitAll()} and also named in
 * {@link #anonymousRoutes()}, because the token check lets a request through without a token only for the
 * routes it is told about.
 */
public interface RouteContributor {

    /**
     * The routes to register.
     *
     * @param services the composed capabilities the handlers use
     * @return the routes; each must declare what it requires
     */
    List<ApiSurfaceRoute> routes(IdentityServices services);

    /**
     * The routes, as {@code "METHOD /path"}, that admit a request without a token.
     *
     * @return the anonymous routes; none by default
     */
    default Set<String> anonymousRoutes() {
        return Set.of();
    }
}
