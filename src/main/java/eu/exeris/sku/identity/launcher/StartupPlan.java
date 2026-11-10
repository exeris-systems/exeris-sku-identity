package eu.exeris.sku.identity.launcher;

import eu.exeris.caps.credentialstore.spi.NotificationDispatcher;
import eu.exeris.kernel.spi.contract.ExecutionEnvironment;
import eu.exeris.sku.identity.auth.MembershipDirectory;
import eu.exeris.sku.identity.config.IdentityConfig;
import eu.exeris.sku.identity.config.IdentityConfigException;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Everything the service needs to start, read and checked before the kernel boots. An incomplete or
 * unusable setting ends in one {@link IdentityConfigException} that lists every problem.
 *
 * @param config                 the identity configuration
 * @param database               the service role's database
 * @param maxPoolSize            largest number of pooled connections
 * @param productionClass        whether the environment serves live traffic
 * @param membershipDirectory    the host's directory, or a stand-in outside production
 * @param notificationDispatcher the delivery channel, or one that delivers nothing
 */
record StartupPlan(IdentityConfig config, DatabaseSettings database, int maxPoolSize, boolean productionClass,
                   MembershipDirectory membershipDirectory, NotificationDispatcher notificationDispatcher) {

    static final String ENVIRONMENT = "EXERIS_ENVIRONMENT";
    static final String DATABASE_PREFIX = "EXERIS_DATABASE";
    static final String DATABASE_MAX_POOL_SIZE = "EXERIS_DATABASE_MAX_POOL_SIZE";
    static final String MEMBERSHIP_DIRECTORY = "EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY";
    static final String NOTIFICATION_DISPATCHER = "EXERIS_IDENTITY_NOTIFICATION_DISPATCHER";

    private static final int DEFAULT_POOL_SIZE = 10;

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
        boolean productionClass = productionClass(in.optional(ENVIRONMENT));
        DatabaseSettings database = DatabaseSettings.read(in, DATABASE_PREFIX);
        int poolSize = in.integer(DATABASE_MAX_POOL_SIZE, DEFAULT_POOL_SIZE, 1, 1000);

        MembershipDirectory directory = hostPart(in, MEMBERSHIP_DIRECTORY, MembershipDirectory.class);
        if (directory == null && in.optional(MEMBERSHIP_DIRECTORY) == null) {
            if (productionClass) {
                in.problem(MEMBERSHIP_DIRECTORY + " must name the host's MembershipDirectory in a "
                        + "production-class environment: this service keeps no membership table of its own.");
            } else {
                directory = new UnconfiguredMembershipDirectory();
            }
        }
        NotificationDispatcher dispatcher = hostPart(in, NOTIFICATION_DISPATCHER, NotificationDispatcher.class);
        if (dispatcher == null && in.optional(NOTIFICATION_DISPATCHER) == null) {
            dispatcher = new UndeliveredNotifications();
        }

        problems.addAll(in.problems());
        if (!problems.isEmpty()) {
            throw new IdentityConfigException(problems);
        }
        return new StartupPlan(config, database, poolSize, productionClass, directory, dispatcher);
    }

    /**
     * The kernel's own settings the plan maps to: the listener, its request limits and the service role's
     * connection pool. The kernel reads them as system properties.
     */
    Map<String, String> kernelProperties() {
        IdentityConfig.Http http = config.http();
        Map<String, String> properties = new LinkedHashMap<>();
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

    /** An environment that is not declared is development; one that is declared and unknown is not. */
    private static boolean productionClass(String declared) {
        if (declared == null) {
            return false;
        }
        return ExecutionEnvironment.fromId(declared).map(ExecutionEnvironment::isProductionClass).orElse(true);
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
