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
import java.util.Set;
import java.util.concurrent.CountDownLatch;

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
 * <p>Every ending of {@code serve} has one exit status and none ends in an uncaught exception: a
 * configuration that cannot be used is {@value #EXIT_CONFIG}, a database that cannot be reached is
 * {@value #EXIT_UNAVAILABLE}, a kernel that did not boot or a service that failed is
 * {@value #EXIT_NOT_COMPLETED}, and a stop on request is 0. An {@code Error} raised while starting, such as
 * a class that cannot be loaded, is the not-completed status; a fatal VM error ends the process with that
 * status without running its hooks. The service is stopped before the kernel stops its subsystems, on every
 * path that returns, and exactly once.
 *
 * <p>A process ended by a termination signal reports the signal's status (143 for SIGTERM on Linux), not 0.
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
    /**
     * Exit status for a command that started but did not complete: {@code bootstrap-owner} that created
     * nothing, and {@code serve} whose kernel did not boot (for example, no licence manifest) or whose
     * service failed while starting, serving or stopping. A {@code serve} that was stopped on request exits 0.
     */
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
        int status;
        try {
            status = switch (command) {
                case "migrate" -> migrate(System.getenv());
                case "bootstrap-owner" -> bootstrapOwner(System.getenv());
                default -> serve(System.getenv());
            };
        } catch (VirtualMachineError fatal) {
            haltAfter(fatal);
            return;
        }
        // Exits unconditionally, for every command: the kernel's transport threads are not daemons, so
        // a main that merely returned would leave the process alive if any of them outlived the kernel's
        // stop. When a termination signal started the shutdown, exit waits for it and the signal's own
        // status (128 + signal) is the one the process reports. No shutdown hook waits for this thread.
        System.exit(status);
    }

    /**
     * The process cannot be trusted to run more code once the VM reports it is out of memory, a stack or
     * another resource. Nothing is handled and no hook is run, because a hook may need the memory that is
     * gone; the process ends at once with the not-completed status. Whatever was started has been unwound
     * on the way here, and the operating system closes what remains. Only an error that reaches the main
     * thread is covered: one raised on another thread leaves that thread's own handler in charge.
     */
    private static void haltAfter(VirtualMachineError fatal) {
        try {
            System.err.println("Identity ended on a fatal VM error (" + fatal.getClass().getName() + ")");
        } catch (Throwable ignored) { // NOPMD - nothing more can be done about a failed report
            // the status below is the report
        }
        Runtime.getRuntime().halt(EXIT_NOT_COMPLETED);
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
        return completing(() -> BootstrapOwnerCommand.run(environment),
                "The owner bootstrap did not complete, nothing was created ({0})");
    }

    /**
     * Runs a command to its exit status so that no ending is an uncaught exception. Anything other than a
     * fatal VM error that the command did not handle is the not-completed status with one ERROR line naming
     * only its class, because its message is not ours to print. A {@link VirtualMachineError} is rethrown for
     * {@link #main} to end the process.
     *
     * @param command the command; returns its exit status
     * @param failureLine the log line, with the class name as argument {@code {0}}
     * @return the exit status
     */
    static int completing(java.util.function.IntSupplier command, String failureLine) {
        try {
            return command.getAsInt();
        } catch (VirtualMachineError fatal) {
            throw fatal;
        } catch (RuntimeException | Error unexpected) {
            LOG.log(System.Logger.Level.ERROR, failureLine, unexpected.getClass().getName());
            return EXIT_NOT_COMPLETED;
        }
    }

    /**
     * Checks the configuration and serves until stopped; returns the process exit status: 0 when stopped on
     * request, {@link #EXIT_CONFIG}, {@link #EXIT_UNAVAILABLE}, or {@link #EXIT_NOT_COMPLETED} when the
     * kernel did not boot or the service failed at any point.
     *
     * <p>An interrupt is a request to stop. When the calling thread's interrupt flag is set on entry, or
     * becomes set before the kernel is asked to boot, nothing is started, no failure is logged, and the
     * result is 0 with the flag still set: building the password encoder, opening the database and booting
     * the kernel all refuse to run on an interrupted thread, and that refusal is not a failure of the service.
     */
    static int serve(Map<String, String> environment) {
        if (interrupted()) {
            LOG.log(System.Logger.Level.INFO, "Asked to stop before starting, nothing was started");
            return exitStatus(Ending.STOPPED);
        }
        // A class that cannot be loaded or initialised, or any failure no step expected, is a start that
        // did not complete.
        return completing(() -> serveChecked(environment), "Identity could not start ({0})");
    }

    private static int serveChecked(Map<String, String> environment) {
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
        if (interrupted()) {
            LOG.log(System.Logger.Level.INFO, "Asked to stop before starting, nothing was started");
            return exitStatus(Ending.STOPPED);
        }
        return exitStatus(run(plan));
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

    /** How a {@code serve} ended; every ending has exactly one exit status, see {@link #exitStatus}. */
    enum Ending {
        /** The service started and was stopped on request: a termination signal or an interrupt. */
        STOPPED,
        /** The kernel did not boot, so nothing was started and no port was bound. */
        KERNEL_NOT_BOOTED,
        /** The service failed while starting, while serving, or while stopping. */
        SERVICE_FAILED
    }

    /**
     * Maps how {@code serve} ended to the process exit status. The switch is exhaustive over {@link Ending}
     * so that a new ending cannot fall through to another status, and an ending that was never produced is
     * the not-completed status, never success.
     *
     * @param ending how the service ended; {@code null} when it was never determined
     * @return the process exit status
     */
    static int exitStatus(Ending ending) {
        return switch (ending) {
            case null -> EXIT_NOT_COMPLETED;
            case STOPPED -> 0;
            case KERNEL_NOT_BOOTED, SERVICE_FAILED -> EXIT_NOT_COMPLETED;
        };
    }

    /** What the kernel's callback ended with; read after the boot returns, on the same thread. */
    private static final class Outcome {
        private boolean serving;
        private Throwable failure;
    }

    private static Ending run(StartupPlan plan) {
        plan.kernelProperties().forEach(System::setProperty);

        SwitchableHandler handler = new SwitchableHandler();
        CountDownLatch shutdown = new CountDownLatch(1);
        ServiceStop stop = new ServiceStop(handler::withdraw);
        Outcome outcome = new Outcome();

        // The hook never waits for the thread that exits the process: it stops the service, which it waits
        // for only when the callback's thread is already stopping it, and releases the latch, which is all
        // the callback is waiting for. Its notice goes straight to the standard error: the logging
        // framework's own shutdown hook runs at the same time as this one and removes the log handlers, so a
        // record published from here can be dropped, while nothing closes the standard error stream.
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            System.err.println("Shutdown signal received, draining");
            stop.stop();
            shutdown.countDown();
        }, "identity-shutdown"));

        LOG.log(System.Logger.Level.INFO, "Booting Exeris Kernel subsystems");
        try {
            ScopedValue.where(HttpKernelProviders.HTTP_SERVER_HANDLER, handler).call(() -> {
                boot(plan, handler, stop, shutdown, outcome);
                return null;
            });
        } catch (VirtualMachineError fatal) {
            throw fatal;
        } catch (Exception e) {
            if (causedByInterrupt(e)) {
                LOG.log(System.Logger.Level.INFO, "Asked to stop while the kernel booted, nothing was started");
                return Ending.STOPPED;
            }
            // Only the kernel can end the callback this way: it records its own failures in the outcome.
            // The licence refusal is a runtime exception, not a BootstrapException. The kernel's message
            // names the gate's code and text; a driver's message may quote the connection URL, so the
            // credentials in it are withheld.
            LOG.log(System.Logger.Level.ERROR, "The kernel did not boot, nothing was started: {0}",
                    LogRedaction.of(e.getMessage(), plan.database().password()));
            return Ending.KERNEL_NOT_BOOTED;
        } catch (Error e) {
            // A class that cannot be loaded or initialised at start is a start that did not complete.
            LOG.log(System.Logger.Level.ERROR, "The kernel did not boot, nothing was started ({0})",
                    e.getClass().getName());
            return Ending.KERNEL_NOT_BOOTED;
        } finally {
            System.clearProperty("exeris.persistence.password");
        }
        if (outcome.failure != null) {
            // A capability's message is not ours to print.
            LOG.log(System.Logger.Level.ERROR, outcome.serving
                    ? "Identity failed after it began serving, stopped ({0})"
                    : "Identity failed while starting, nothing is serving ({0})",
                    outcome.failure.getClass().getName());
            return Ending.SERVICE_FAILED;
        }
        return Ending.STOPPED;
    }

    /**
     * Runs on the thread that called {@code serve}, inside the kernel's callback. Nothing but a fatal VM
     * error leaves it: the ending is recorded in {@code outcome}, and the service is stopped before the
     * callback returns so that the kernel stops its subsystems only after the service has drained.
     */
    private static void boot(StartupPlan plan, SwitchableHandler handler, ServiceStop stop,
                             CountDownLatch shutdown, Outcome outcome) throws KernelBootstrap.BootstrapException {
        KernelBootstrap.builder()
                .selector(BootstrapSelector.forNames(SUBSYSTEMS.toArray(String[]::new)))
                .build()
                .boot(() -> {
                    try {
                        // The pool is open; the secret need not stay readable in the process properties.
                        System.clearProperty("exeris.persistence.password");
                        if (interrupted()) {
                            // Asked to stop before anything was built: building refuses an interrupted thread.
                            return;
                        }
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
                        if (!interrupted() && stop.admit(() -> built.stop(DRAIN))) {
                            // Host parts are created before the kernel boots; they get the executor now,
                            // before start() runs any job and before handler.serve() lets any request in.
                            plan.joinTransactions(built.transactionalExecutor());
                            if (interrupted()) {
                                // Asked to stop while a host part ran: refuse the start through the stop.
                                reportStopFailure(stop.stop(), outcome);
                            }
                            if (!built.tryStart()) {
                                // A stop won between the admission and the start: nothing is started.
                                return;
                            }
                            if (interrupted()) {
                                // Asked to stop while the composition started: it never serves.
                                return;
                            }
                            handler.serve(built.httpHandler());
                            outcome.serving = true;
                            if (!interrupted()) {
                                LOG.log(System.Logger.Level.INFO, "Exeris Identity running on {0}:{1}",
                                        plan.config().http().bindHost(), plan.config().http().port());
                            }
                            shutdown.await();
                        }
                    } catch (InterruptedException e) {
                        // An interrupt asks the service to stop; it is not a failure.
                        Thread.currentThread().interrupt();
                    } catch (VirtualMachineError fatal) {
                        throw fatal;
                    } catch (Exception | Error e) {
                        // A refusal of the interrupt by a step that waits is a stop, not a failure.
                        if (!causedByInterrupt(e)) {
                            outcome.failure = e;
                        }
                    } finally {
                        reportStopFailure(stop.stop(), outcome);
                    }
                });
    }

    /**
     * Whether the serving thread has been asked to stop, which is what an interrupt means. The flag is read
     * and not cleared, so that {@code shutdown.await()} still sees it and every later check agrees.
     */
    private static boolean interrupted() {
        return Thread.currentThread().isInterrupted();
    }

    /**
     * Whether a failure is the refusal of an interrupt that is still pending: the calling thread's interrupt
     * flag is set and an {@link InterruptedException}, an {@link java.io.InterruptedIOException} or a
     * {@link java.nio.channels.ClosedByInterruptException} is in the cause chain. Each of those is raised
     * only by an interrupt, and a step that refuses one restores the flag, so the pair identifies a failure
     * that the interrupt caused. A failure without such a cause, or one after which the flag was cleared, is
     * not recognised and stays a failure.
     */
    static boolean causedByInterrupt(Throwable failure) {
        if (!interrupted()) {
            return false;
        }
        Set<Throwable> seen = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        for (Throwable cause = failure; cause != null && seen.add(cause); cause = cause.getCause()) {
            if (cause instanceof InterruptedException || cause instanceof java.io.InterruptedIOException
                    || cause instanceof java.nio.channels.ClosedByInterruptException) {
                return true;
            }
        }
        return false;
    }

    private static void reportStopFailure(Throwable stopFailure, Outcome outcome) {
        if (stopFailure != null) {
            LOG.log(System.Logger.Level.ERROR, "Stopping Identity failed ({0})", stopFailure.getClass().getName());
            if (outcome.failure == null) {
                outcome.failure = stopFailure;
            }
        }
    }

    private static JobScheduler scheduler() {
        return KernelProviders.JOB_SCHEDULER.isBound() ? KernelProviders.JOB_SCHEDULER.get() : null;
    }
}
