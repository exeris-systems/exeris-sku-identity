package eu.exeris.sku.identity.http;

import eu.exeris.kernel.spi.http.HttpStatus;

/**
 * The fixed set of errors a route can answer with. A caller sees the status and the stable code, never the
 * text of an exception, so nothing about the inside of the service or about another account leaks.
 */
public enum Problem {

    /** The body or a field is missing, malformed or out of range. */
    INVALID_REQUEST(HttpStatus.BAD_REQUEST, "invalid_request"),
    /** The body is larger than the service accepts. */
    REQUEST_TOO_LARGE(HttpStatus.CONTENT_TOO_LARGE, "request_too_large"),
    /** The body is not declared as JSON. */
    UNSUPPORTED_MEDIA_TYPE(new HttpStatus(415, "Unsupported Media Type"), "unsupported_media_type"),
    /** The login or password is wrong, or the account is locked; the three are not told apart. */
    INVALID_CREDENTIALS(HttpStatus.UNAUTHORIZED, "invalid_credentials"),
    /** The password of an already signed-in caller is wrong. */
    WRONG_PASSWORD(HttpStatus.FORBIDDEN, "wrong_password"),
    /** The password was right but the mailbox is not verified yet. */
    ACCOUNT_UNVERIFIED(HttpStatus.FORBIDDEN, "account_unverified"),
    /** Too many failed attempts on an account the caller is signed in to. */
    ACCOUNT_LOCKED(HttpStatus.TOO_MANY_REQUESTS, "account_locked"),
    /** The second-factor challenge is unknown, used or expired. */
    INVALID_CHALLENGE(HttpStatus.UNAUTHORIZED, "invalid_challenge"),
    /** The challenge took too many wrong codes. */
    CHALLENGE_LOCKED(HttpStatus.TOO_MANY_REQUESTS, "challenge_locked"),
    /** The second-factor code or recovery code is wrong. */
    INVALID_MFA_CODE(HttpStatus.UNAUTHORIZED, "invalid_mfa_code"),
    /** The refresh token is unknown, used, revoked or expired. */
    INVALID_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "invalid_refresh_token"),
    /** A verification or reset token is unknown, used, superseded or expired. */
    INVALID_TOKEN(HttpStatus.BAD_REQUEST, "invalid_token"),
    /** The new password does not satisfy the password policy. */
    INVALID_PASSWORD(HttpStatus.BAD_REQUEST, "invalid_password"),
    /** The new password equals the current one. */
    SAME_PASSWORD(HttpStatus.BAD_REQUEST, "same_password"),
    /** The invitation does not exist for this tenant and address, or is spent. */
    INVALID_INVITATION(HttpStatus.BAD_REQUEST, "invalid_invitation"),
    /** The address already has an account. */
    ACCOUNT_EXISTS(HttpStatus.CONFLICT, "account_exists"),
    /** The caller may not do this. */
    FORBIDDEN(HttpStatus.FORBIDDEN, "forbidden"),
    /** The caller's token names no tenant, and the call needs one. */
    TENANT_REQUIRED(HttpStatus.FORBIDDEN, "tenant_required"),
    /** The second factor is already active. */
    FACTOR_ALREADY_ENROLLED(HttpStatus.CONFLICT, "factor_already_enrolled"),
    /** The second factor is not active, so there is nothing to do. */
    FACTOR_NOT_ENROLLED(HttpStatus.CONFLICT, "factor_not_enrolled"),
    /** The second-factor enrolment code is wrong. */
    INVALID_CODE(HttpStatus.BAD_REQUEST, "invalid_code"),
    /** There is nothing with that identifier that belongs to the caller. */
    NOT_FOUND(HttpStatus.NOT_FOUND, "not_found"),
    /** Something failed inside the service. */
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "internal_error");

    private final HttpStatus status;
    private final String code;

    Problem(HttpStatus status, String code) {
        this.status = status;
        this.code = code;
    }

    /** The HTTP status. */
    public HttpStatus status() {
        return status;
    }

    /** The stable, machine-readable code. */
    public String code() {
        return code;
    }

    /** Raises this problem; the route guard turns it into the response. */
    Failure raise() {
        return new Failure(this);
    }

    /** Carries a {@link Problem} out of a handler without a stack trace. */
    static final class Failure extends RuntimeException {

        private static final long serialVersionUID = 1L;

        private final Problem problem;

        private Failure(Problem problem) {
            super(problem.code, null, false, false);
            this.problem = problem;
        }

        Problem problem() {
            return problem;
        }
    }
}
