package eu.exeris.sku.identity;

import eu.exeris.caps.audittrail.api.AuditLogSink;
import eu.exeris.caps.credentialstore.api.AccountVerification;
import eu.exeris.caps.credentialstore.api.CredentialProvisioning;
import eu.exeris.caps.credentialstore.api.CredentialRecovery;
import eu.exeris.caps.credentialstore.api.CredentialStore;
import eu.exeris.caps.i18n.api.LocaleResolver;
import eu.exeris.caps.i18n.api.TranslationRegistry;
import eu.exeris.caps.invitations.api.InvitationService;
import eu.exeris.caps.mfatotp.api.MfaChallenge;
import eu.exeris.caps.mfatotp.api.RecoveryCodes;
import eu.exeris.caps.mfatotp.api.TotpFactorRegistry;
import eu.exeris.caps.mfatotp.api.TotpVerifier;
import eu.exeris.caps.sessionmanagement.api.RefreshTokenRotation;
import eu.exeris.caps.sessionmanagement.api.SessionStore;
import eu.exeris.caps.sessionmanagement.spi.AccessTokenIssuer;
import eu.exeris.caps.tokenissuer.api.JwksPublisher;
import eu.exeris.sku.identity.auth.MembershipDirectory;
import eu.exeris.sku.identity.config.IdentityConfig;

import java.time.Clock;

/**
 * The composed capabilities a route handler works with.
 *
 * <p>{@code credentialProvisioning} creates an already-verified account without a password check of any
 * kind: a route may call it only after the caller has proved control of the mailbox by other means, such
 * as holding a pending invitation.
 *
 * @param config                the validated configuration
 * @param clock                 the clock lifetimes are measured by
 * @param credentialStore       passwords, lockout and password change
 * @param accountVerification   mailbox verification
 * @param credentialRecovery    password reset
 * @param credentialProvisioning creation of verified accounts
 * @param sessions              sessions of a subject
 * @param refreshTokens         refresh-token issue, rotation and revocation
 * @param sessionAccessTokens   access tokens for a subject and session, with tenant, role and scopes
 * @param totpFactors           second-factor enrolment
 * @param totpVerifier          second-factor code checks
 * @param recoveryCodes         second-factor recovery codes
 * @param mfaChallenges         the challenge between a correct password and a second factor
 * @param invitations           invitations into a tenant
 * @param memberships           where tenant memberships live
 * @param jwks                  the published signing keys
 * @param audit                 the audit sink every capability records to
 * @param localeResolver        locale selection for fixed messages
 * @param translations          the fixed message set
 */
public record IdentityServices(
        IdentityConfig config,
        Clock clock,
        CredentialStore credentialStore,
        AccountVerification accountVerification,
        CredentialRecovery credentialRecovery,
        CredentialProvisioning credentialProvisioning,
        SessionStore sessions,
        RefreshTokenRotation refreshTokens,
        AccessTokenIssuer sessionAccessTokens,
        TotpFactorRegistry totpFactors,
        TotpVerifier totpVerifier,
        RecoveryCodes recoveryCodes,
        MfaChallenge mfaChallenges,
        InvitationService invitations,
        MembershipDirectory memberships,
        JwksPublisher jwks,
        AuditLogSink audit,
        LocaleResolver localeResolver,
        TranslationRegistry translations) {
}
