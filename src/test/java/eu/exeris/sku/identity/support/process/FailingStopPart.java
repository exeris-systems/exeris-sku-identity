package eu.exeris.sku.identity.support.process;

import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import eu.exeris.sku.identity.auth.JoinsServiceTransactions;
import eu.exeris.sku.identity.auth.Membership;
import eu.exeris.sku.identity.auth.MembershipDirectory;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.LogManager;

/**
 * A host directory that makes the stop of a serving launcher fail, in a JVM that was started with
 * {@code --add-opens java.base/java.lang=ALL-UNNAMED}. The capabilities and the switchable handler are
 * not reachable from a host part, so once the service is serving a helper thread finds the launcher's
 * shutdown hook, takes the stop it holds, the composition the stop drains and the withdrawal it runs first, and
 * replaces them with stand-ins whose failures are chosen by the environment. Every failure is a thrown
 * {@link Error} whose message carries the marker; none is a {@link VirtualMachineError} unless asked for.
 */
public final class FailingStopPart implements MembershipDirectory, JoinsServiceTransactions {

    /** The variable listing what fails: any of {@value #WITHDRAW}, {@value #DRAIN}, {@value #TERMINATE}, {@value #DRAIN_FATAL}. */
    public static final String FAIL_VARIABLE = "IDENTITY_TEST_STOP_FAILS";
    /** The variable holding the text of every message. */
    public static final String MARKER_VARIABLE = "IDENTITY_TEST_STOP_MARKER";
    /** When {@code true}, the log handlers are removed once the failures are arranged, as the logging framework's hook does. */
    public static final String REMOVE_HANDLERS_VARIABLE = "IDENTITY_TEST_STOP_REMOVE_HANDLERS";
    /** When {@code true}, the serving thread is interrupted once the failures are arranged, so that it performs the stop. */
    public static final String INTERRUPT_VARIABLE = "IDENTITY_TEST_STOP_INTERRUPT_SERVER";

    /** The withdrawal of the handler fails with a {@link WithdrawalError}. */
    public static final String WITHDRAW = "withdraw";
    /** The drain of a capability fails with a {@link DrainError}. */
    public static final String DRAIN = "drain";
    /** The termination of a capability fails with a {@link TerminateError}. */
    public static final String TERMINATE = "terminate";
    /** The drain of a capability fails with an {@link OutOfMemoryError}. */
    public static final String DRAIN_FATAL = "drain-fatal";

    /** Written to the standard error once the failures are in place. */
    public static final String ARRANGED_LINE = "stop failures arranged";
    /** Written to the standard error when the arrangement could not be made. */
    public static final String FAILED_LINE = "stop failures could not be arranged";

    /** Thrown by the withdrawal. */
    public static final class WithdrawalError extends Error {
        private static final long serialVersionUID = 1L;

        WithdrawalError(String message) {
            super(message);
        }
    }

    /** Thrown by a drain. */
    public static final class DrainError extends Error {
        private static final long serialVersionUID = 1L;

        DrainError(String message) {
            super(message);
        }
    }

    /** Thrown by a termination. */
    public static final class TerminateError extends Error {
        private static final long serialVersionUID = 1L;

        TerminateError(String message) {
            super(message);
        }
    }

    @Override
    public void joinTransactionsOf(TransactionalExecutor executor) {
        Thread serving = Thread.currentThread();
        Object handler = eu.exeris.kernel.spi.http.HttpKernelProviders.HTTP_SERVER_HANDLER.get();
        Thread arranger = new Thread(() -> arrange(serving, handler), "stop-failure-arranger");
        arranger.setDaemon(true);
        arranger.start();
    }

    private static void arrange(Thread serving, Object handler) {
        try {
            Field handlerField = field(handler.getClass(), "target");
            @SuppressWarnings("unchecked")
            AtomicReference<Object> target = (AtomicReference<Object>) handlerField.get(handler);
            long deadline = System.nanoTime() + Duration.ofSeconds(90).toNanos();
            while (target.get() == null) {
                if (System.nanoTime() > deadline) {
                    throw new IllegalStateException("never served");
                }
                Thread.sleep(10);
            }
            List<String> fails = List.of(System.getenv(FAIL_VARIABLE).split(","));
            String marker = System.getenv(MARKER_VARIABLE);

            Object stop = stopOf(hook());
            Object state = ((AtomicReference<?>) field(stop.getClass(), "state").get(stop)).get();
            Object action = field(state.getClass(), "action").get(state);
            Object composition = null;
            for (Field captured : action.getClass().getDeclaredFields()) {
                captured.setAccessible(true);
                Object value = captured.get(action);
                if (value != null && value.getClass().getName().equals("eu.exeris.sku.identity.IdentityComposition")) {
                    composition = value;
                }
            }
            if (composition == null) {
                throw new IllegalStateException("no composition in the stop");
            }
            if (fails.contains(DRAIN) || fails.contains(TERMINATE) || fails.contains(DRAIN_FATAL)) {
                Field order = field(composition.getClass(), "readyOrder");
                @SuppressWarnings("unchecked")
                List<Object> modules = new ArrayList<>((List<Object>) order.get(composition));
                modules.set(0, failing(modules.get(0), fails, marker));
                order.set(composition, List.copyOf(modules));
            }
            if (fails.contains(WITHDRAW)) {
                Field withdrawField = field(stop.getClass(), "withdraw");
                Runnable real = (Runnable) withdrawField.get(stop);
                withdrawField.set(stop, (Runnable) () -> {
                    real.run();
                    throw new WithdrawalError("withdrawal: " + marker);
                });
            }
            if (Boolean.parseBoolean(System.getenv(REMOVE_HANDLERS_VARIABLE))) {
                LogManager.getLogManager().reset();
            }
            System.err.println(ARRANGED_LINE);
            if (Boolean.parseBoolean(System.getenv(INTERRUPT_VARIABLE))) {
                serving.interrupt();
            }
        } catch (ReflectiveOperationException | RuntimeException | InterruptedException e) {
            System.err.println(FAILED_LINE + " " + e.getClass().getName() + " " + e.getMessage());
        }
    }

    /** The launcher's shutdown hook thread, found among the JVM's registered hooks. */
    private static Thread hook() throws ReflectiveOperationException {
        Class<?> hooks = Class.forName("java.lang.ApplicationShutdownHooks");
        Field registered = hooks.getDeclaredField("hooks");
        registered.setAccessible(true);
        Map<?, ?> map = (Map<?, ?>) registered.get(null);
        synchronized (hooks) {
            for (Object key : new ArrayList<>(map.keySet())) {
                if (key instanceof Thread thread && "identity-shutdown".equals(thread.getName())) {
                    return thread;
                }
            }
        }
        throw new IllegalStateException("no shutdown hook of the launcher");
    }

    /** The service stop that the hook's task captured. */
    private static Object stopOf(Thread hook) throws ReflectiveOperationException {
        Object holder = field(Thread.class, "holder").get(hook);
        Object task = field(holder.getClass(), "task").get(holder);
        for (Field captured : task.getClass().getDeclaredFields()) {
            captured.setAccessible(true);
            Object value = captured.get(task);
            if (value != null && value.getClass().getSimpleName().equals("ServiceStop")) {
                return value;
            }
        }
        throw new IllegalStateException("no stop in the hook");
    }

    private static Field field(Class<?> type, String name) throws ReflectiveOperationException {
        Field field = type.getDeclaredField(name);
        field.setAccessible(true);
        return field;
    }

    /** The capability, with its drain and its termination failing as chosen. */
    private static Object failing(Object module, List<String> fails, String marker) {
        Class<?> hooks = module.getClass().getInterfaces()[0];
        for (Class<?> type : allInterfaces(module.getClass())) {
            if (type.getName().equals("eu.exeris.sdk.composition.lifecycle.CapabilityLifecycleHooks")) {
                hooks = type;
            }
        }
        InvocationHandler handler = (proxy, method, args) -> {
            if (method.getName().equals("drain") && fails.contains(DRAIN_FATAL)) {
                throw new OutOfMemoryError("drain: " + marker);
            }
            if (method.getName().equals("drain") && fails.contains(DRAIN)) {
                throw new DrainError("drain: " + marker);
            }
            if (method.getName().equals("terminate") && fails.contains(TERMINATE)) {
                throw new TerminateError("terminate: " + marker);
            }
            try {
                return method.invoke(module, args);
            } catch (InvocationTargetException e) {
                throw e.getCause();
            }
        };
        return Proxy.newProxyInstance(module.getClass().getClassLoader(), new Class<?>[]{hooks}, handler);
    }

    private static List<Class<?>> allInterfaces(Class<?> type) {
        List<Class<?>> found = new ArrayList<>();
        for (Class<?> c = type; c != null; c = c.getSuperclass()) {
            for (Class<?> i : c.getInterfaces()) {
                found.add(i);
                found.addAll(allInterfaces(i));
            }
        }
        return found;
    }

    @Override
    public List<Membership> memberships(UUID subjectId) {
        return List.of();
    }

    @Override
    public void grant(UUID tenantId, UUID subjectId, String role) {
        throw new IllegalStateException("unreachable");
    }
}
