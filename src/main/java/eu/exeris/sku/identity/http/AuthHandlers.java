package eu.exeris.sku.identity.http;

import eu.exeris.caps.mfatotp.api.model.IssuedChallenge;
import eu.exeris.caps.sessionmanagement.api.IssuedAccessToken;
import eu.exeris.caps.sessionmanagement.api.RotationOutcome;
import eu.exeris.caps.credentialstore.api.model.CredentialVerificationResult;
import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.sku.identity.IdentityServices;

import java.util.Arrays;
import java.util.Set;
import java.util.UUID;

/** Sign-in with a password and the refresh of a session. */
final class AuthHandlers {

    private static final int MAX_EMAIL = 254;
    private static final int MAX_REFRESH_TOKEN = 512;

    private final IdentityServices services;
    private final JsonBodies bodies;
    private final Responses responses;
    private final SessionIssuance sessions;

    AuthHandlers(IdentityServices services, JsonBodies bodies, Responses responses, SessionIssuance sessions) {
        this.services = services;
        this.bodies = bodies;
        this.responses = responses;
        this.sessions = sessions;
    }

    /**
     * Checks the password. A wrong password, an unknown login and a locked account answer alike, so the
     * answer does not say whether an account exists. A correct password on an unverified mailbox says so,
     * because only the holder of the password gets that far. A second factor, when enrolled, turns the
     * answer into a challenge.
     */
    void login(HttpExchange exchange) {
        JsonBodies.Fields body = bodies.read(exchange, Set.of("email", "password"));
        String email = body.string("email", MAX_EMAIL);
        char[] password = body.password("password");
        CredentialVerificationResult result;
        try {
            result = services.credentialStore().authenticate(email, password);
        } finally {
            Arrays.fill(password, '\0');
        }
        switch (result.status()) {
            case INVALID, LOCKED -> throw Problem.INVALID_CREDENTIALS.raise();
            case UNVERIFIED -> throw Problem.ACCOUNT_UNVERIFIED.raise();
            case SUCCESS -> {
                UUID subject = result.subjectId();
                if (services.totpFactors().getStatus(subject).enabled()) {
                    IssuedChallenge challenge = services.mfaChallenges()
                            .issue(subject, services.config().mfa().challengeTtl());
                    responses.json(exchange, HttpStatus.OK, Responses.object(
                            "mfaRequired", true,
                            "challengeToken", challenge.challengeToken(),
                            "expiresAt", challenge.expiresAt().toString()));
                } else {
                    responses.json(exchange, HttpStatus.OK, sessions.open(subject, exchange));
                }
            }
        }
    }

    /**
     * Exchanges a refresh token for its successor and a new access token. A token that was already used
     * revokes its session; every refusal answers alike.
     */
    void refresh(HttpExchange exchange) {
        JsonBodies.Fields body = bodies.read(exchange, Set.of("refreshToken"));
        String token = body.string("refreshToken", MAX_REFRESH_TOKEN);
        RotationOutcome outcome = services.refreshTokens().rotate(token, SessionIssuance.client(exchange));
        if (outcome instanceof RotationOutcome.Rotated rotated) {
            IssuedAccessToken access = rotated.findAccessToken().orElseGet(
                    () -> services.sessionAccessTokens().issueAccessToken(rotated.subjectId(), rotated.sessionId()));
            responses.json(exchange, HttpStatus.OK,
                    sessions.describe(rotated.sessionId(), access, rotated.refreshToken()));
            return;
        }
        throw Problem.INVALID_REFRESH_TOKEN.raise();
    }
}
