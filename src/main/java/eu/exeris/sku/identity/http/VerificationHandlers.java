package eu.exeris.sku.identity.http;

import eu.exeris.caps.credentialstore.api.exception.InvalidTokenException;
import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.sku.identity.IdentityServices;

import java.util.Set;

/** Proving control of a mailbox. */
final class VerificationHandlers {

    private static final int MAX_EMAIL = 254;
    private static final int MAX_TOKEN = 512;

    private final IdentityServices services;
    private final JsonBodies bodies;
    private final Responses responses;

    VerificationHandlers(IdentityServices services, JsonBodies bodies, Responses responses) {
        this.services = services;
        this.bodies = bodies;
        this.responses = responses;
    }

    /** Sends a verification token when the address has an unverified account. The answer is the same either way. */
    void send(HttpExchange exchange) {
        JsonBodies.Fields body = bodies.read(exchange, Set.of("email"));
        services.accountVerification().issueVerification(body.string("email", MAX_EMAIL));
        responses.json(exchange, HttpStatus.ACCEPTED, Responses.object("status", "accepted"));
    }

    /** Marks the account verified with the token the owner of the mailbox received. */
    void verify(HttpExchange exchange) {
        JsonBodies.Fields body = bodies.read(exchange, Set.of("token"));
        try {
            services.accountVerification().verifyAccount(body.string("token", MAX_TOKEN));
        } catch (InvalidTokenException e) {
            throw Problem.INVALID_TOKEN.raise();
        }
        responses.json(exchange, HttpStatus.OK, Responses.object("verified", true));
    }
}
