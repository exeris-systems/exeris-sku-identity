package eu.exeris.sku.identity.http;

import eu.exeris.caps.mfatotp.api.exception.ChallengeLockedException;
import eu.exeris.caps.mfatotp.api.exception.FactorAlreadyEnrolledException;
import eu.exeris.caps.mfatotp.api.exception.FactorNotFoundException;
import eu.exeris.caps.mfatotp.api.exception.InvalidChallengeException;
import eu.exeris.caps.mfatotp.api.exception.InvalidRecoveryCodeException;
import eu.exeris.caps.mfatotp.api.exception.InvalidTotpCodeException;
import eu.exeris.caps.mfatotp.api.model.ChallengeStatus;
import eu.exeris.caps.mfatotp.api.model.RecoveryCodeBatch;
import eu.exeris.caps.mfatotp.api.model.TotpEnrollmentSession;
import eu.exeris.caps.sessionmanagement.api.SessionPrincipal;
import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.sku.identity.IdentityServices;

import java.util.Set;
import java.util.UUID;

/** The second factor: the challenge after a password, and enrolment and recovery codes of the signed-in caller. */
final class MfaHandlers {

    /** How many recovery codes a regeneration yields. */
    static final int RECOVERY_CODE_COUNT = 10;

    private static final int MAX_CHALLENGE_TOKEN = 512;
    private static final int MAX_CODE = 64;
    private static final int MAX_LABEL = 128;

    private final IdentityServices services;
    private final JsonBodies bodies;
    private final Responses responses;
    private final SessionIssuance sessions;

    MfaHandlers(IdentityServices services, JsonBodies bodies, Responses responses, SessionIssuance sessions) {
        this.services = services;
        this.bodies = bodies;
        this.responses = responses;
        this.sessions = sessions;
    }

    /**
     * Completes a sign-in with a time-based code or a recovery code. Every wrong code counts against the
     * challenge, which locks after a fixed number; the subject is the one the challenge was issued for.
     */
    void verify(HttpExchange exchange) {
        JsonBodies.Fields body = bodies.read(exchange, Set.of("challengeToken", "code", "recoveryCode"));
        String challengeToken = body.string("challengeToken", MAX_CHALLENGE_TOKEN);
        if (body.has("code") == body.has("recoveryCode")) {
            throw Problem.INVALID_REQUEST.raise();
        }
        ChallengeStatus status;
        try {
            status = services.mfaChallenges().validate(challengeToken);
        } catch (ChallengeLockedException e) {
            throw Problem.CHALLENGE_LOCKED.raise();
        } catch (InvalidChallengeException e) {
            throw Problem.INVALID_CHALLENGE.raise();
        }
        UUID subject = status.subjectId();
        boolean accepted;
        if (body.has("code")) {
            accepted = services.totpVerifier().verify(subject, body.string("code", MAX_CODE));
        } else {
            try {
                accepted = services.recoveryCodes().verifyAndConsume(subject, body.string("recoveryCode", MAX_CODE));
            } catch (InvalidRecoveryCodeException e) {
                accepted = false;
            }
        }
        if (!accepted) {
            services.mfaChallenges().recordFailure(challengeToken);
            throw Problem.INVALID_MFA_CODE.raise();
        }
        UUID consumed;
        try {
            consumed = services.mfaChallenges().consume(challengeToken);
        } catch (InvalidChallengeException e) {
            throw Problem.INVALID_CHALLENGE.raise();
        }
        if (!subject.equals(consumed)) {
            throw Problem.INVALID_CHALLENGE.raise();
        }
        responses.json(exchange, HttpStatus.OK, sessions.open(consumed, exchange));
    }

    /** Starts enrolment of the caller's authenticator and returns the secret to load into it. */
    void beginEnrollment(HttpExchange exchange) {
        JsonBodies.Fields body = bodies.readOptional(exchange, Set.of("accountLabel"));
        UUID subject = SessionPrincipal.current().subjectId();
        String label = body.optionalString("accountLabel", MAX_LABEL).orElse(subject.toString());
        try {
            TotpEnrollmentSession enrollment = services.totpFactors().beginEnrollment(subject, label);
            responses.json(exchange, HttpStatus.OK, Responses.object(
                    "secret", enrollment.secret(),
                    "provisioningUri", enrollment.provisioningUri()));
        } catch (FactorAlreadyEnrolledException e) {
            throw Problem.FACTOR_ALREADY_ENROLLED.raise();
        }
    }

    /** Activates the caller's pending enrolment with a code from the authenticator. */
    void confirmEnrollment(HttpExchange exchange) {
        JsonBodies.Fields body = bodies.read(exchange, Set.of("code"));
        UUID subject = SessionPrincipal.current().subjectId();
        try {
            services.totpFactors().confirmEnrollment(subject, body.string("code", MAX_CODE));
            responses.json(exchange, HttpStatus.OK, Responses.object("enabled", true));
        } catch (InvalidTotpCodeException e) {
            throw Problem.INVALID_CODE.raise();
        } catch (FactorNotFoundException e) {
            throw Problem.FACTOR_NOT_ENROLLED.raise();
        }
    }

    /** Replaces the caller's recovery codes with a fresh batch, shown once. */
    void regenerateRecoveryCodes(HttpExchange exchange) {
        bodies.requireEmpty(exchange);
        UUID subject = SessionPrincipal.current().subjectId();
        if (!services.totpFactors().getStatus(subject).enabled()) {
            throw Problem.FACTOR_NOT_ENROLLED.raise();
        }
        RecoveryCodeBatch batch = services.recoveryCodes().regenerate(subject, RECOVERY_CODE_COUNT);
        responses.json(exchange, HttpStatus.OK, Responses.object(
                "codes", batch.rawCodes(),
                "generatedAt", batch.generatedAt().toString()));
    }
}
