package eu.exeris.sku.identity.http;

import eu.exeris.caps.sessionmanagement.api.SessionInfo;
import eu.exeris.caps.sessionmanagement.api.SessionPrincipal;
import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.sku.identity.IdentityServices;

import java.util.List;
import java.util.Set;
import java.util.UUID;

/** The sessions of the signed-in caller. Every operation acts on the subject of the caller's token alone. */
final class SessionHandlers {

    private final IdentityServices services;
    private final JsonBodies bodies;
    private final Responses responses;

    SessionHandlers(IdentityServices services, JsonBodies bodies, Responses responses) {
        this.services = services;
        this.bodies = bodies;
        this.responses = responses;
    }

    /** Lists the caller's active sessions, marking the one the token belongs to. */
    void list(HttpExchange exchange) {
        bodies.requireEmpty(exchange);
        List<SessionInfo> infos = services.sessions().listSessions(SessionPrincipal.current());
        List<Object> items = infos.stream().map(SessionHandlers::describe).toList();
        responses.json(exchange, HttpStatus.OK, Responses.object("sessions", items));
    }

    /** Revokes one of the caller's sessions; another subject's session is indistinguishable from none. */
    void revoke(HttpExchange exchange) {
        JsonBodies.Fields body = bodies.read(exchange, Set.of("sessionId"));
        UUID sessionId = body.uuid("sessionId");
        if (!services.sessions().revokeSession(SessionPrincipal.current(), sessionId)) {
            throw Problem.NOT_FOUND.raise();
        }
        responses.json(exchange, HttpStatus.OK, Responses.object("revoked", 1));
    }

    /** Revokes every session of the caller, the current one included. */
    void revokeAll(HttpExchange exchange) {
        bodies.requireEmpty(exchange);
        int revoked = services.sessions().revokeAllSessions(SessionPrincipal.current());
        responses.json(exchange, HttpStatus.OK, Responses.object("revoked", revoked));
    }

    private static Object describe(SessionInfo info) {
        return Responses.object(
                "id", info.id().toString(),
                "createdAt", info.createdAt().toString(),
                "lastActiveAt", info.lastActiveAt().toString(),
                "expiresAt", info.expiresAt().toString(),
                "userAgent", info.userAgent(),
                "ipAddress", info.ipAddress(),
                "current", info.isCurrent());
    }
}
