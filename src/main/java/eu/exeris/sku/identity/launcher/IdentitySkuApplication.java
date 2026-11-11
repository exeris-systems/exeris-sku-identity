package eu.exeris.sku.identity.launcher;

import eu.exeris.kernel.community.security.Argon2idPasswordEncoder;
import eu.exeris.kernel.core.bootstrap.KernelBootstrap;
import eu.exeris.kernel.spi.bootstrap.BootstrapSelector;
import eu.exeris.kernel.spi.context.KernelProviders;
import eu.exeris.kernel.spi.contract.ExecutionEnvironment;
import eu.exeris.kernel.spi.http.HttpKernelProviders;
import eu.exeris.kernel.spi.scheduling.JobScheduler;
import eu.exeris.sku.identity.IdentityComposition;
import eu.exeris.sku.identity.config.IdentityConfigException;
import eu.exeris.sku.identity.http.IdentityRoutes;

import java.sql.SQLException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Runnable entry point of the Exeris Identity SKU.
 *
 * <p>{@code serve} (the default) reads and checks the whole configuration, then boots the kernel's HTTP,
 * transport, persistence and scheduling subsystems, composes the capabilities over the kernel's
 * transactional executor and serves until told to stop. A configuration the service cannot use ends the
 * process before the kernel starts. {@code migrate} applies the schema with a separate, privileged
 * database role and exits. {@code bootstrap-owner} creates the first verified account on a migrated database
 * that has none, without starting the HTTP service, and exits.
 *
 * <p>Only this package names a kernel driver, the Argon2id password encoder: this class for {@code serve}
 * and {@link BootstrapOwnerCommand} for {@code bootstrap-owner}. The library surface takes a
 * {@code KernelPasswordEncoder} from its host.
 *
 * <p>TLS is not provided: the listener is plaintext and expects TLS to be terminated in front of it.
 */
public final class IdentitySkuApplication {

    /** Exit status for a configuration that cannot be used (BSD sysexits EX_CONFIG). */
    public static final int EXIT_CONFIG = 78;
    /** Exit status for a database that cannot be reached (BSD sysexits EX_UNAVAILABLE). */
    public static final int EXIT_UNAVAILABLE = 69;
    /** Exit status for a command line that is not understood (BSD sysexits EX_USAGE). */
    public static final int EXIT_USAGE = 64;
    /** Exit status for a database in which the credential store's schema is not migrated for the service role. */
    public static final int EXIT_NOT_MIGRATED = 65;
    /** Exit status for a command that started but could not finish; nothing was committed. */
    public static final int EXIT_NOT_COMPLETED = 70;
    /** Exit status for {@code bootstrap-owner} refused because an account already exists. */
    public static final int EXIT_ACCOUNTS_EXIST = 73;
    /** Exit status for a migration the database refused. */
    public static final int EXIT_MIGRATION_FAILED = 1;

    private static final System.Logger LOG = System.getLogger(IdentitySkuApplication.class.getName());
    private static final Duration DRAIN = Duration.ofSeconds(15);
    private static final List<String> SUBSYSTEMS = List.of("http", "transport", "persistence", "scheduling");

    private IdentitySkuApplication() {
    }

    public static void main(String[] args) {
        String command = args.length == 0 ? "serve" : args[0];
        if (args.length > 1 || !(command.equals("serve") || command.equals("migrate")
                || command.equals("bootstrap-owner"))) {
            LOG.log(System.Logger.Level.ERROR, "Usage: IdentitySkuApplication [serve | migrate | bootstrap-owner]");
            System.exit(EXIT_USAGE);
            return;
        }
        if (command.equals("bootstrap-owner")) {
            // Exits unconditionally: a kernel thread must not keep a finished one-shot command alive.
            System.exit(bootstrapOwner(System.getenv()));
            return;
        }
        int status = command.equals("migrate") ? migrate(System.getenv()) : serve(System.getenv());
        if (status != 0) {
            System.exit(status);
        }
    }

    /** Applies the schema; returns the process exit status. */
    static int migrate(Map<String, String> environment) {
        try {
            List<String> applied = Migrate.run(environment);
            LOG.log(System.Logger.Level.INFO, applied.isEmpty()
                    ? "The schema is current, nothing to apply"
                    : "Applied " + applied.size() + " migration(s): " + applied);
            return 0;
        } catch (IdentityConfigException e) {
            LOG.log(System.Logger.Level.ERROR, "Migration configuration refused: {0}", e.getMessage());
            return EXIT_CONFIG;
        } catch (SQLException e) {
            LOG.log(System.Logger.Level.ERROR, "Migration failed, SQLSTATE {0}: {1}", e.getSQLState(), e.getMessage());
            return EXIT_MIGRATION_FAILED;
        }
    }

    /** Creates the first verified account; returns the process exit status. */
    static int bootstrapOwner(Map<String, String> environment) {
        return BootstrapOwnerCommand.run(environment);
    }

    /** Checks the configuration and serves until stopped; returns the process exit status. */
    static int serve(Map<String, String> environment) {
        StartupPlan plan;
        try {
            plan = StartupPlan.prepare(environment);
            requireSameEnvironment(plan);
            ServiceRoleCheck.verify(plan.database());
        } catch (IdentityConfigException e) {
            LOG.log(System.Logger.Level.ERROR, "Identity configuration refused, not starting: {0}", e.getMessage());
            return EXIT_CONFIG;
        } catch (SQLException e) {
            LOG.log(System.Logger.Level.ERROR, "The database cannot be reached, not starting (SQLSTATE {0})",
                    e.getSQLState());
            return EXIT_UNAVAILABLE;
        }
        run(plan);
        return 0;
    }

    /** The kernel reads its environment from a system property; it must name the one this service was given. */
    static void requireSameEnvironment(StartupPlan plan) {
        String property = System.getProperty("exeris.environment");
        if (property != null && !property.isBlank()
                && !ExecutionEnvironment.fromId(property).filter(plan.environment()::equals).isPresent()) {
            throw new IdentityConfigException(List.of("The system property exeris.environment disagrees with "
                    + StartupPlan.ENVIRONMENT + ": the kernel and this service must run in one environment."));
        }
    }

    private static void run(StartupPlan plan) {
        plan.kernelProperties().forEach(System::setProperty);

        SwitchableHandler handler = new SwitchableHandler();
        CountDownLatch shutdown = new CountDownLatch(1);
        AtomicReference<IdentityComposition> composition = new AtomicReference<>();

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            LOG.log(System.Logger.Level.INFO, "Shutdown signal received, draining");
            handler.withdraw();
            IdentityComposition running = composition.get();
            if (running != null) {
                running.stop(DRAIN);
            }
            shutdown.countDown();
        }, "identity-shutdown"));

        LOG.log(System.Logger.Level.INFO, "Booting Exeris Kernel subsystems");
        ScopedValue.where(HttpKernelProviders.HTTP_SERVER_HANDLER, handler)
                .run(() -> boot(plan, handler, composition, shutdown));
    }

    private static void boot(StartupPlan plan, SwitchableHandler handler,
                             AtomicReference<IdentityComposition> composition,
                             CountDownLatch shutdown) {
        try {
            KernelBootstrap.builder()
                    .selector(BootstrapSelector.forNames(SUBSYSTEMS.toArray(String[]::new)))
                    .build()
                    .boot(() -> {
                        try {
                            // The pool is open; the secret need not stay readable in the process properties.
                            System.clearProperty("exeris.persistence.password");
                            IdentityComposition.Builder builder = IdentityComposition.builder()
                                    .config(plan.config())
                                    .transactionalExecutor(KernelProviders.transactionalExecutor())
                                    .passwordEncoder(new Argon2idPasswordEncoder(plan.config().passwordHashing()))
                                    .notificationDispatcher(plan.notificationDispatcher())
                                    .membershipDirectory(plan.membershipDirectory())
                                    .jobScheduler(scheduler())
                                    .routes(new IdentityRoutes(plan.config()));
                            if (plan.invitationDelivery() != null) {
                                builder.invitationDelivery(plan.invitationDelivery());
                            }
                            IdentityComposition built = builder.build();
                            composition.set(built);
                            // Host parts are created before the kernel boots; they get the executor now,
                            // before start() runs any job and before handler.serve() lets any request in.
                            plan.joinTransactions(built.transactionalExecutor());
                            built.start();
                            handler.serve(built.httpHandler());
                            LOG.log(System.Logger.Level.INFO, "Exeris Identity running on {0}:{1}",
                                    plan.config().http().bindHost(), plan.config().http().port());
                            shutdown.await();
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        } catch (Exception e) {
                            throw new IllegalStateException("Identity lifecycle failed", e);
                        }
                    });
        } catch (KernelBootstrap.BootstrapException e) {
            throw new IllegalStateException("Kernel boot failed", e);
        }
    }

    private static JobScheduler scheduler() {
        return KernelProviders.JOB_SCHEDULER.isBound() ? KernelProviders.JOB_SCHEDULER.get() : null;
    }
}
