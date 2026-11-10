package eu.exeris.sku.identity.launcher;

import eu.exeris.caps.credentialstore.spi.NotificationDispatcher;
import eu.exeris.kernel.spi.contract.ExecutionEnvironment;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import eu.exeris.sku.identity.auth.InvitationDelivery;
import eu.exeris.sku.identity.auth.JoinsServiceTransactions;
import eu.exeris.sku.identity.auth.MembershipDirectory;
import eu.exeris.sku.identity.config.IdentityConfig;
import eu.exeris.sku.identity.config.IdentityConfigException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Everything the service needs to start, read and checked before the kernel boots. An incomplete or
 * unusable setting ends in one {@link IdentityConfigException} that lists every problem.
 *
 * <p>The environment must be declared, because the kernel and this service must act on one value: an
 * undeclared environment would make the kernel run as development while this service guessed otherwise.
 *
 * @param config                 the identity configuration
 * @param database               the service role's database
 * @param maxPoolSize            largest number of pooled connections
 * @param environment            the declared execution environment
 * @param membershipDirectory    the host's directory, or a stand-in outside production-class environments
 * @param notificationDispatcher the delivery channel, or one that delivers nothing outside production-class
 *                               environments
 * @param invitationDelivery     the host's invitation delivery; null outside production-class environments
 *                               when none is named
 */
record StartupPlan(IdentityConfig config, DatabaseSettings database, int maxPoolSize,
                   ExecutionEnvironment environment, MembershipDirectory membershipDirectory,
                   NotificationDispatcher notificationDispatcher, InvitationDelivery invitationDelivery) {

    static final String ENVIRONMENT = "EXERIS_ENVIRONMENT";
    static final String DATABASE_PREFIX = "EXERIS_DATABASE";
    static final String DATABASE_MAX_POOL_SIZE = "EXERIS_DATABASE_MAX_POOL_SIZE";
    static final String MEMBERSHIP_DIRECTORY = "EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY";
    static final String NOTIFICATION_DISPATCHER = "EXERIS_IDENTITY_NOTIFICATION_DISPATCHER";
    static final String INVITATION_DELIVERY = "EXERIS_IDENTITY_INVITATION_DELIVERY";

    private static final int DEFAULT_POOL_SIZE = 10;
    private static final System.Logger LOG = System.getLogger(StartupPlan.class.getName());
    private static final String KNOWN_ENVIRONMENTS = Arrays.stream(ExecutionEnvironment.values())
            .map(ExecutionEnvironment::id).collect(Collectors.joining(" | "));

    /**
     * Reads and checks every setting.
     *
     * @param environment the process environment
     * @return the plan
     * @throws IdentityConfigException listing every setting that is missing or unusable
     */
    static StartupPlan prepare(Map<String, String> environment) {
        List<String> problems = new ArrayList<>();
        IdentityConfig config = null;
        try {
            config = IdentityConfig.load(environment);
        } catch (IdentityConfigException e) {
            problems.addAll(e.problems());
        }

        LauncherEnvironment in = new LauncherEnvironment(environment);
        ExecutionEnvironment declared = declaredEnvironment(in);
        boolean productionClass = declared != null && declared.isProductionClass();
        DatabaseSettings database = DatabaseSettings.read(in, DATABASE_PREFIX);
        int poolSize = in.integer(DATABASE_MAX_POOL_SIZE, DEFAULT_POOL_SIZE, 1, 1000);

        MembershipDirectory directory = hostPart(in, MEMBERSHIP_DIRECTORY, MembershipDirectory.class);
        NotificationDispatcher dispatcher = hostPart(in, NOTIFICATION_DISPATCHER, NotificationDispatcher.class);
        InvitationDelivery delivery = hostPart(in, INVITATION_DELIVERY, InvitationDelivery.class);
        if (declared != null) {
            if (directory == null && in.optional(MEMBERSHIP_DIRECTORY) == null) {
                if (productionClass) {
                    in.problem(MEMBERSHIP_DIRECTORY + " must name the host's MembershipDirectory in a "
                            + "production-class environment: this service keeps no membership table of its own.");
                } else {
                    LOG.log(System.Logger.Level.WARNING, "{0} is not set: nobody belongs to any tenant, so tokens "
                            + "name no tenant and no invitation can be issued", MEMBERSHIP_DIRECTORY);
                    directory = new UnconfiguredMembershipDirectory();
                }
            }
            if (dispatcher == null && in.optional(NOTIFICATION_DISPATCHER) == null) {
                if (productionClass) {
                    in.problem(NOTIFICATION_DISPATCHER + " must name the host's NotificationDispatcher in a "
                            + "production-class environment: verification and reset tokens would reach nobody.");
                } else {
                    LOG.log(System.Logger.Level.WARNING, "{0} is not set: verification and password-reset tokens "
                            + "are not delivered", NOTIFICATION_DISPATCHER);
                    dispatcher = new UndeliveredNotifications();
                }
            }
            if (delivery == null && in.optional(INVITATION_DELIVERY) == null) {
                if (productionClass) {
                    in.problem(INVITATION_DELIVERY + " must name the host's InvitationDelivery in a "
                            + "production-class environment: an invitation token would reach nobody.");
                } else {
                    LOG.log(System.Logger.Level.WARNING, "{0} is not set: issuing an invitation is refused",
                            INVITATION_DELIVERY);
                }
            }
        }

        problems.addAll(in.problems());
        if (!problems.isEmpty()) {
            throw new IdentityConfigException(problems);
        }
        return new StartupPlan(config, database, poolSize, declared, directory, dispatcher, delivery);
    }

    /**
     * Hands the executor that joins the composition's units to every loaded host part that asks for it.
     * Parts are created before the kernel boots, so none can receive it at construction; the launcher calls
     * this once the composition exists and before anything can call a part. A part that serves more than
     * one role is handed it once.
     *
     * @param executor the composition's {@code transactionalExecutor()}
     */
    void joinTransactions(TransactionalExecutor executor) {
        Set<Object> handed = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Object part : new Object[]{membershipDirectory, notificationDispatcher, invitationDelivery}) {
            if (part instanceof JoinsServiceTransactions joins && handed.add(part)) {
                joins.joinTransactionsOf(executor);
            }
        }
    }

    /**
     * The kernel's own settings the plan maps to: the declared environment, the listener, its request
     * limits and the service role's connection pool. The kernel reads them as system properties.
     *
     * <p>Row-level security is always on: the invitations table is protected by a policy that reads the
     * tenant the kernel publishes for the transaction, and the kernel publishes it only when this is set.
     * A system property outranks the environment variable, so an operator cannot switch it off.
     */
    Map<String, String> kernelProperties() {
        IdentityConfig.Http http = config.http();
        Map<String, String> properties = new LinkedHashMap<>();
        properties.put("exeris.environment", environment.id());
        properties.put("exeris.persistence.rlsEnabled", "true");
        properties.put("exeris.http.mode", "SERVER");
        properties.put("exeris.http.bindHost", http.bindHost());
        properties.put("exeris.http.port", String.valueOf(http.port()));
        properties.put("exeris.http.maxRequestBodyBytes", String.valueOf(http.maxRequestBodyBytes()));
        properties.put("exeris.http.maxRequestHeaderCount", String.valueOf(http.maxRequestHeaderCount()));
        properties.put("exeris.http.maxRequestHeaderSize", String.valueOf(http.maxRequestHeaderSize()));
        properties.put("exeris.persistence.jdbcUrl", database.url());
        properties.put("exeris.persistence.username", database.user());
        properties.put("exeris.persistence.password", database.password());
        properties.put("exeris.persistence.maxPoolSize", String.valueOf(maxPoolSize));
        return properties;
    }

    /** The declared environment; a missing or unknown one is a problem, never a default. */
    private static ExecutionEnvironment declaredEnvironment(LauncherEnvironment in) {
        String declared = in.optional(ENVIRONMENT);
        if (declared == null) {
            in.problem(ENVIRONMENT + " is not set: declare one of " + KNOWN_ENVIRONMENTS + ".");
            return null;
        }
        Optional<ExecutionEnvironment> known = ExecutionEnvironment.fromId(declared);
        if (known.isEmpty()) {
            in.problem(ENVIRONMENT + " names an environment that does not exist: declare one of "
                    + KNOWN_ENVIRONMENTS + ".");
        }
        return known.orElse(null);
    }

    private static <T> T hostPart(LauncherEnvironment in, String key, Class<T> type) {
        String className = in.optional(key);
        if (className == null) {
            return null;
        }
        try {
            Class<?> loaded = Class.forName(className, true, StartupPlan.class.getClassLoader());
            if (!type.isAssignableFrom(loaded)) {
                in.problem(key + " names a class that is not a " + type.getSimpleName() + ".");
                return null;
            }
            return type.cast(loaded.getDeclaredConstructor().newInstance());
        } catch (ReflectiveOperationException | LinkageError e) {
            in.problem(key + " names a class that cannot be loaded with a public no-argument constructor ("
                    + e.getClass().getSimpleName() + ").");
            return null;
        }
    }
}
