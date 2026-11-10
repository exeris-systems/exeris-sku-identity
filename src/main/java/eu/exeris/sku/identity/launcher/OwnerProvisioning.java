package eu.exeris.sku.identity.launcher;

import eu.exeris.caps.credentialstore.api.CredentialProvisioning;
import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.PersistenceStatement;
import eu.exeris.kernel.spi.persistence.QueryResult;
import eu.exeris.sku.identity.auth.MembershipDirectory;
import eu.exeris.sku.identity.auth.RoleScopes;
import eu.exeris.sku.identity.auth.TenantScope;
import eu.exeris.sku.identity.persistence.JoiningTransactionalExecutor;

import java.util.Arrays;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Creates the first account and, when the host keeps memberships, makes it the owner of a tenant, in one
 * transaction: either the account exists and holds the role, or nothing was written.
 *
 * <p>Two runs against one empty database are serialised by a transaction-scoped advisory lock taken as the
 * first statement of the unit. The run that gets the lock second starts its emptiness check after the first
 * has committed or rolled back, so it sees the account or finds the table still empty.
 */
final class OwnerProvisioning {

    /** The advisory lock key; distinct from the migrations' key. */
    static final long ADVISORY_LOCK_KEY = 0x1D3A_7157_0000_0002L;

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

    /** An account existed once the lock was held; nothing was written. */
    record AccountsExist() implements Outcome {
    }

    /** The credential store refused the address. It carries no message, so the address cannot leak. */
    static final class InvalidLoginIdentifier extends RuntimeException {
        InvalidLoginIdentifier() {
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
     */
    static Outcome provision(JoiningTransactionalExecutor tx, CredentialProvisioning provisioning,
                             MembershipDirectory directory, String email, char[] password, UUID tenantId,
                             UUID subjectId) {
        Supplier<Outcome> work = () -> {
            tx.executeManaged(connection -> lock(connection));
            if (anyAccount(tx)) {
                return new AccountsExist();
            }
            char[] attempt = password.clone();
            try {
                provisioning.provisionVerified(subjectId, email, attempt);
            } catch (IllegalArgumentException e) {
                throw new InvalidLoginIdentifier();
            } finally {
                Arrays.fill(attempt, '\0');
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

    private static void lock(PersistenceConnection connection) {
        try (QueryResult ignored = connection.executeQuery("SELECT pg_advisory_xact_lock(" + ADVISORY_LOCK_KEY + ")")) {
            // the lock is held until the transaction ends
        }
    }

    private static boolean anyAccount(JoiningTransactionalExecutor tx) {
        return tx.query(connection -> {
            try (PersistenceStatement statement = connection.prepare(
                    "SELECT count(*) FROM (SELECT 1 FROM credential_records LIMIT 1) AS found");
                 QueryResult rows = statement.executeQuery()) {
                return rows.next() && rows.row().getLong(0) > 0;
            }
        });
    }
}
