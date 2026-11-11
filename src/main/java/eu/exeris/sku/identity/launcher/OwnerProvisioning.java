package eu.exeris.sku.identity.launcher;

import eu.exeris.caps.credentialstore.api.CredentialProvisioning;
import eu.exeris.caps.credentialstore.api.model.ProvisionResult;
import eu.exeris.sku.identity.auth.MembershipDirectory;
import eu.exeris.sku.identity.auth.RoleScopes;
import eu.exeris.sku.identity.auth.TenantScope;
import eu.exeris.sku.identity.persistence.JoiningTransactionalExecutor;

import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Creates the first account and, when the host keeps memberships, makes it the owner of a tenant, in one
 * transaction: either the account exists and holds the role, or nothing was written.
 *
 * <p>Whether an account already exists is decided by the credential store, not here:
 * {@link CredentialProvisioning#provisionFirstVerified} checks and inserts atomically against every
 * concurrent writer of credentials. Its call is the first statement of the unit, so its exclusion holds at
 * any isolation level; the unit runs at read committed in any case, the only level the joining executor
 * admits. The membership grant follows it in the same transaction and commits or rolls back with it.
 */
final class OwnerProvisioning {

    /** What a run did. */
    sealed interface Outcome permits Provisioned, AccountsExist {
    }

    /**
     * The account was created and committed.
     *
     * @param subjectId the new account
     * @param tenantId  the tenant it owns; null when no directory is configured
     */
    record Provisioned(UUID subjectId, UUID tenantId) implements Outcome {
    }

    /** The deployment already held an account; nothing was written. */
    record AccountsExist() implements Outcome {
    }

    /** The credential store refused the address. It carries no message, so the address cannot leak. */
    static final class InvalidLoginIdentifier extends RuntimeException {
        InvalidLoginIdentifier() {
            super(null, null, false, false);
        }
    }

    /** The credential table is under row-level security, so no deployment-wide answer exists. No message. */
    static final class CredentialTableUnderRowLevelSecurity extends RuntimeException {
        CredentialTableUnderRowLevelSecurity() {
            super(null, null, false, false);
        }
    }

    private OwnerProvisioning() {
    }

    /**
     * Provisions the account. The unit may run more than once when the database asks for a retry, so every
     * attempt gets its own copy of the password and uses the same subject; the grant is idempotent.
     *
     * @param tx           the composition's joining executor
     * @param provisioning the credential store's administrative provisioning, built over {@code tx}
     * @param directory    the host's directory, joined to {@code tx}; null when none is configured
     * @param email        the address of the account
     * @param password     the password; the caller zeroes it
     * @param tenantId     the tenant to grant ownership in; null exactly when {@code directory} is null
     * @param subjectId    the id of the new account, chosen once by the caller
     * @return the outcome
     * @throws InvalidLoginIdentifier when the credential store refuses the address; nothing was written
     * @throws CredentialTableUnderRowLevelSecurity when the credential store refuses to answer for a table
     *                                              under row-level security; nothing was written
     */
    static Outcome provision(JoiningTransactionalExecutor tx, CredentialProvisioning provisioning,
                             MembershipDirectory directory, String email, char[] password, UUID tenantId,
                             UUID subjectId) {
        Supplier<Outcome> work = () -> {
            char[] attempt = password.clone();
            Optional<ProvisionResult> created;
            try {
                // The first statement of the unit: nothing is read or written before it.
                created = provisioning.provisionFirstVerified(subjectId, email, attempt);
            } catch (IllegalArgumentException e) {
                throw new InvalidLoginIdentifier();
            } catch (IllegalStateException e) {
                throw new CredentialTableUnderRowLevelSecurity();
            } finally {
                Arrays.fill(attempt, '\0');
            }
            if (created.isEmpty()) {
                return new AccountsExist();
            }
            if (directory != null) {
                directory.grant(tenantId, subjectId, RoleScopes.OWNER);
            }
            return new Provisioned(subjectId, tenantId);
        };
        // The tenant is bound outside the unit: a unit is pinned to the isolation key it began under.
        return tenantId == null
                ? tx.inTransaction(work)
                : TenantScope.call(tenantId, () -> tx.inTransaction(work));
    }
}
