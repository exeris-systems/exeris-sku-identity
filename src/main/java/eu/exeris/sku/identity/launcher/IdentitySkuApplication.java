package eu.exeris.sku.identity.launcher;

import eu.exeris.kernel.community.security.Argon2idPasswordEncoder;
import eu.exeris.kernel.core.bootstrap.KernelBootstrap;
import eu.exeris.kernel.spi.bootstrap.BootstrapSelector;
import eu.exeris.kernel.spi.context.KernelProviders;
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
 * database role and exits.
 *
 * <p>This is the only class that names a kernel driver: the Argon2id password encoder. The library surface
 * takes a {@code KernelPasswordEncoder} from its host.
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
    /** Exit status for a migration the database refused. */
    public static final int EXIT_MIGRATION_FAILED = 1;

    private static final System.Logger LOG = System.getLogger(IdentitySkuApplication.class.getName());
    private static final Duration DRAIN = Duration.ofSeconds(15);
    private static final List<String> SUBSYSTEMS = List.of("http", "transport", "persistence", "scheduling");

    private IdentitySkuApplication() {
    }

    public static void main(String[] args) {
        String command = args.length == 0 ? "serve" : args[0];
        if (args.length > 1 || !(command.equals("serve") || command.equals("migrate"))) {
            LOG.log(System.Logger.Level.ERROR, "Usage: IdentitySkuApplication [serve | migrate]");
            System.exit(EXIT_USAGE);
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

    /** Checks the configuration and serves until stopped; returns the process exit status. */
    static int serve(Map<String, String> environment) {
        StartupPlan plan;
        try {
            plan = StartupPlan.prepare(environment);
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
                            IdentityComposition built = IdentityComposition.builder()
                                    .config(plan.config())
                                    .transactionalExecutor(KernelProviders.transactionalExecutor())
                                    .passwordEncoder(new Argon2idPasswordEncoder(plan.config().passwordHashing()))
                                    .notificationDispatcher(plan.notificationDispatcher())
                                    .membershipDirectory(plan.membershipDirectory())
                                    .jobScheduler(scheduler())
                                    .routes(new IdentityRoutes(plan.config()))
                                    .build();
                            composition.set(built);
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
