package eu.exeris.sku.identity.http;

import eu.exeris.caps.credentialstore.api.exception.AccountLockedException;
import eu.exeris.caps.credentialstore.api.exception.InvalidCredentialException;
import eu.exeris.caps.credentialstore.api.exception.InvalidTokenException;
import eu.exeris.caps.credentialstore.api.exception.SamePasswordException;
import eu.exeris.caps.sessionmanagement.api.SessionPrincipal;
import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.sku.identity.IdentityServices;

import java.util.Arrays;
import java.util.Set;

/** Changing and resetting a password. A change or a reset ends every session of the account. */
final class PasswordHandlers {

    private static final int MAX_EMAIL = 254;
    private static final int MAX_TOKEN = 512;

    private final IdentityServices services;
    private final JsonBodies bodies;
    private final Responses responses;

    PasswordHandlers(IdentityServices services, JsonBodies bodies, Responses responses) {
        this.services = services;
        this.bodies = bodies;
        this.responses = responses;
    }

    /** Changes the password of the signed-in caller after checking the current one. */
    void change(HttpExchange exchange) {
        JsonBodies.Fields body = bodies.read(exchange, Set.of("currentPassword", "newPassword"));
        char[] current = body.password("currentPassword");
        char[] replacement = body.password("newPassword");
        try {
            services.credentialStore().changePassword(SessionPrincipal.current().subjectId(), current, replacement);
        } catch (InvalidCredentialException e) {
            throw Problem.WRONG_PASSWORD.raise();
        } catch (AccountLockedException e) {
            throw Problem.ACCOUNT_LOCKED.raise();
        } catch (SamePasswordException e) {
            throw Problem.SAME_PASSWORD.raise();
        } catch (IllegalArgumentException e) {
            throw Problem.INVALID_PASSWORD.raise();
        } finally {
            Arrays.fill(current, '\0');
            Arrays.fill(replacement, '\0');
        }
        responses.noContent(exchange);
    }

    /** Sends a reset token to the address when an account has it. The answer is the same either way. */
    void requestReset(HttpExchange exchange) {
        JsonBodies.Fields body = bodies.read(exchange, Set.of("email"));
        services.credentialRecovery().requestReset(body.string("email", MAX_EMAIL));
        responses.json(exchange, HttpStatus.ACCEPTED, Responses.object("status", "accepted"));
    }

    /** Sets a new password with a reset token the owner of the mailbox received. */
    void reset(HttpExchange exchange) {
        JsonBodies.Fields body = bodies.read(exchange, Set.of("token", "newPassword"));
        String token = body.string("token", MAX_TOKEN);
        char[] replacement = body.password("newPassword");
        try {
            services.credentialRecovery().consumeReset(token, replacement);
        } catch (InvalidTokenException e) {
            throw Problem.INVALID_TOKEN.raise();
        } catch (SamePasswordException e) {
            throw Problem.SAME_PASSWORD.raise();
        } catch (IllegalArgumentException e) {
            throw Problem.INVALID_PASSWORD.raise();
        } finally {
            Arrays.fill(replacement, '\0');
        }
        responses.noContent(exchange);
    }
}
