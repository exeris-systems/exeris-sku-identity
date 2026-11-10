package eu.exeris.sku.identity.http;

import eu.exeris.caps.sessionmanagement.api.ClientMetadata;
import eu.exeris.caps.sessionmanagement.api.IssuedAccessToken;
import eu.exeris.caps.sessionmanagement.api.IssuedRefreshToken;
import eu.exeris.caps.sessionmanagement.api.Session;
import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.sku.identity.IdentityServices;
import eu.exeris.sku.identity.wiring.PeerAddresses;

import java.util.Map;
import java.util.UUID;

/** Opens a session for a subject that has proved who it is, and describes the tokens that go with it. */
final class SessionIssuance {

    private static final int MAX_USER_AGENT = 512;
    private static final int MAX_ADDRESS = 64;

    private final IdentityServices services;

    SessionIssuance(IdentityServices services) {
        this.services = services;
    }

    /**
     * Creates a session with its first refresh token and an access token.
     *
     * @param subject  the subject whose sign-in just succeeded; never a value taken from a request
     * @param exchange the request, for the client's description
     * @return the response body
     */
    Map<String, Object> open(UUID subject, HttpExchange exchange) {
        Session session = services.sessions().createSession(subject, client(exchange));
        IssuedRefreshToken refresh = services.refreshTokens().issue(session.id(), subject);
        IssuedAccessToken access = services.sessionAccessTokens().issueAccessToken(subject, session.id());
        return describe(session.id(), access, refresh);
    }

    /** The response body for a set of tokens. */
    Map<String, Object> describe(UUID sessionId, IssuedAccessToken access, IssuedRefreshToken refresh) {
        return Responses.object(
                "tokenType", access.tokenType(),
                "accessToken", access.token(),
                "expiresAt", access.expiresAt().toString(),
                "refreshToken", refresh.rawToken(),
                "refreshExpiresAt", refresh.expiresAt().toString(),
                "sessionId", sessionId.toString());
    }

    /** What the client says about itself, bounded. */
    static ClientMetadata client(HttpExchange exchange) {
        String userAgent = exchange.request().firstHeader("User-Agent")
                .map(String::strip)
                .map(SessionIssuance::printable)
                .map(value -> value.length() > MAX_USER_AGENT ? value.substring(0, MAX_USER_AGENT) : value)
                .filter(value -> !value.isEmpty())
                .orElse(null);
        String address = PeerAddresses.current(exchange).orElse(null);
        if (address != null && (address.isBlank() || address.length() > MAX_ADDRESS)) {
            address = null;
        }
        return ClientMetadata.of(userAgent, address);
    }

    private static String printable(String value) {
        StringBuilder out = new StringBuilder(value.length());
        value.codePoints().filter(c -> !Character.isISOControl(c)).forEach(out::appendCodePoint);
        return out.toString();
    }
}
