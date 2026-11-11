package eu.exeris.sku.identity.launcher;

import eu.exeris.caps.credentialstore.api.exception.CredentialAlreadyExistsException;
import eu.exeris.kernel.community.security.Argon2idPasswordEncoder;
import eu.exeris.kernel.core.bootstrap.KernelBootstrap;
import eu.exeris.kernel.spi.bootstrap.BootstrapSelector;
import eu.exeris.kernel.spi.context.KernelProviders;
import eu.exeris.kernel.spi.exceptions.persistence.PersistenceProviderException;
import eu.exeris.sku.identity.IdentityComposition;
import eu.exeris.sku.identity.config.IdentityConfigException;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * The {@code bootstrap-owner} subcommand: creates the first verified account on a migrated database that
 * holds none, and makes it the owner of a tenant when the host keeps memberships.
 *
 * <p>Configuration, the password file and the service role are checked before the kernel boots, with plain
 * database reads as the service role. Whether the schema is migrated and whether an account exists are the
 * credential store's to answer, through its provisioning API, so those two refusals come from inside the
 * transaction and need the kernel to have booted. The kernel boots its persistence and scheduling subsystems
 * and no listener. The composition is built and never started, so no job runs and no signing key is touched,
 * and no token is issued.
 *
 * <p>The command runs on one thread: the pre-checks, the kernel's callback and the mapping of the outcome to
 * a status all execute on the caller's thread, one after the other.
 */
final class BootstrapOwnerCommand {

    private static final System.Logger LOG = System.getLogger(BootstrapOwnerCommand.class.getName());

    /** SQLSTATE of a relation that does not exist. */
    private static final String UNDEFINED_TABLE = "42P01";
    /** SQLSTATE of a relation the role may not use. */
    private static final String INSUFFICIENT_PRIVILEGE = "42501";

    private BootstrapOwnerCommand() {
    }

    /** What the kernel's callback ended with; read after the boot returns, on the same thread. */
    private static final class Result {
        private OwnerProvisioning.Outcome outcome;
        private RuntimeException failure;
    }

    /**
     * Runs the command.
     *
     * @param environment the process environment
     * @return the process exit status
     */
    static int run(Map<String, String> environment) {
        char[] password = null;
        try {
            StartupPlan plan;
            BootstrapOwnerSettings settings;
            try {
                plan = StartupPlan.prepare(environment);
                IdentitySkuApplication.requireSameEnvironment(plan);
                LauncherEnvironment in = new LauncherEnvironment(environment);
                settings = BootstrapOwnerSettings.read(in, plan.hasMembershipDirectory());
                if (settings != null) {
                    password = PasswordFile.read(settings.passwordFile(), plan.config().credentials().password(), in);
                }
                if (!in.problems().isEmpty()) {
                    throw new IdentityConfigException(new ArrayList<>(in.problems()));
                }
                ServiceRoleCheck.verify(plan.database());
            } catch (IdentityConfigException e) {
                LOG.log(System.Logger.Level.ERROR, "Owner bootstrap refused, nothing changed: {0}", e.getMessage());
                return IdentitySkuApplication.EXIT_CONFIG;
            }
            return provision(plan, settings, password);
        } catch (SQLException e) {
            LOG.log(System.Logger.Level.ERROR, "The database cannot be reached, nothing changed (SQLSTATE {0})",
                    e.getSQLState());
            return IdentitySkuApplication.EXIT_UNAVAILABLE;
        } finally {
            if (password != null) {
                Arrays.fill(password, '\0');
            }
        }
    }

    private static int provision(StartupPlan plan, BootstrapOwnerSettings settings, char[] password) {
        plan.persistenceProperties().forEach(System::setProperty);
        Result result = new Result();
        try {
            KernelBootstrap.builder()
                    .selector(BootstrapSelector.forNames("persistence", "scheduling"))
                    .build()
                    .boot(() -> {
                        try {
                            // The pool is open; the secret need not stay readable in the process properties.
                            System.clearProperty("exeris.persistence.password");
                            result.outcome = compose(plan, settings, password);
                        } catch (RuntimeException e) {
                            result.failure = e;
                        }
                    });
        } catch (KernelBootstrap.BootstrapException | RuntimeException e) {
            // The kernel's licence refusal is a runtime exception, not a BootstrapException.
            LOG.log(System.Logger.Level.ERROR, "The kernel did not boot, nothing was created: {0}", e.getMessage());
            return IdentitySkuApplication.EXIT_NOT_COMPLETED;
        }
        if (result.failure != null) {
            return failed(result.failure);
        }
        return exitStatus(result.outcome);
    }

    /**
     * Maps an outcome to the process exit status. An outcome that was never produced is never reported as a
     * refusal or as success: it is the not-completed status, and the switch is exhaustive over the sealed
     * outcome type so that a new outcome cannot fall through to another status.
     *
     * @param outcome what the provisioning ended with; {@code null} when it never ran
     * @return the process exit status
     */
    static int exitStatus(OwnerProvisioning.Outcome outcome) {
        return switch (outcome) {
            case null -> {
                LOG.log(System.Logger.Level.ERROR, "The provisioning did not run and nothing changed.");
                yield IdentitySkuApplication.EXIT_NOT_COMPLETED;
            }
            case OwnerProvisioning.Provisioned created -> {
                report(created);
                yield 0;
            }
            case OwnerProvisioning.AccountsExist exists -> accountsExist();
        };
    }

    private static OwnerProvisioning.Outcome compose(StartupPlan plan, BootstrapOwnerSettings settings,
                                                     char[] password) {
        IdentityComposition.Builder builder = IdentityComposition.builder()
                .config(plan.config())
                .transactionalExecutor(KernelProviders.transactionalExecutor())
                .passwordEncoder(new Argon2idPasswordEncoder(plan.config().passwordHashing()))
                .notificationDispatcher(plan.notificationDispatcher())
                .membershipDirectory(plan.membershipDirectory())
                .jobScheduler(KernelProviders.JOB_SCHEDULER.isBound() ? KernelProviders.JOB_SCHEDULER.get() : null);
        if (plan.invitationDelivery() != null) {
            builder.invitationDelivery(plan.invitationDelivery());
        }
        // Built, never started: the composition only supplies the wiring of the credential store.
        IdentityComposition built = builder.build();
        plan.joinTransactions(built.transactionalExecutor());
        return OwnerProvisioning.provision(built.transactionalExecutor(), built.credentialProvisioning(),
                plan.hasMembershipDirectory() ? plan.membershipDirectory() : null,
                settings.email(), password, settings.tenantId(), UUID.randomUUID());
    }

    private static int failed(RuntimeException failure) {
        if (failure instanceof OwnerProvisioning.InvalidLoginIdentifier) {
            LOG.log(System.Logger.Level.ERROR, "{0} is not a usable address. Nothing changed.",
                    BootstrapOwnerSettings.EMAIL);
            return IdentitySkuApplication.EXIT_CONFIG;
        }
        if (failure instanceof OwnerProvisioning.CredentialTableUnderRowLevelSecurity) {
            LOG.log(System.Logger.Level.ERROR, "The credential table must not be under row-level security: the "
                    + "first account is decided for the whole deployment. Nothing changed.");
            return IdentitySkuApplication.EXIT_CONFIG;
        }
        if (failure instanceof CredentialAlreadyExistsException) {
            return accountsExist();
        }
        if (schemaUnusable(failure)) {
            LOG.log(System.Logger.Level.ERROR, "The schema is not migrated for this service role: run "
                    + "migrate first. Nothing changed.");
            return IdentitySkuApplication.EXIT_NOT_MIGRATED;
        }
        // A host directory's message is not ours to print.
        LOG.log(System.Logger.Level.ERROR, "The owner account was not created and nothing was committed ({0})",
                failure.getClass().getName());
        return IdentitySkuApplication.EXIT_NOT_COMPLETED;
    }

    /** Whether the database reported an undefined table or insufficient privilege anywhere in the chain. */
    private static boolean schemaUnusable(Throwable failure) {
        for (Throwable t = failure; t != null; t = t.getCause()) {
            if (t instanceof SQLException sql && isSchemaState(sql.getSQLState())) {
                return true;
            }
            if (t instanceof PersistenceProviderException ppe && ppe.rawArgs().length > 0
                    && ppe.rawArgs()[0] instanceof String state && isSchemaState(state)) {
                return true;
            }
            if (t.getCause() == t) {
                break;
            }
        }
        return false;
    }

    private static boolean isSchemaState(String sqlState) {
        return UNDEFINED_TABLE.equals(sqlState) || INSUFFICIENT_PRIVILEGE.equals(sqlState);
    }

    private static int accountsExist() {
        LOG.log(System.Logger.Level.ERROR, "An account already exists: bootstrap-owner only creates the first one. "
                + "Nothing changed.");
        return IdentitySkuApplication.EXIT_ACCOUNTS_EXIST;
    }

    private static void report(OwnerProvisioning.Provisioned created) {
        if (created.tenantId() != null) {
            LOG.log(System.Logger.Level.INFO, "Owner account {0} created and verified; role owner granted in tenant {1}",
                    created.subjectId(), created.tenantId());
        } else {
            LOG.log(System.Logger.Level.WARNING, "Owner account {0} created and verified; no membership directory "
                    + "is configured, so it belongs to no tenant: its tokens name no tenant and carry no role or "
                    + "scope, and it cannot issue invitations", created.subjectId());
        }
    }
}
