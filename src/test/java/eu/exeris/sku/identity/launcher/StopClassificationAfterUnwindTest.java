package eu.exeris.sku.identity.launcher;

import eu.exeris.caps.serviceboundarycore.ServiceBoundaryCoreModule;
import eu.exeris.kernel.community.security.Argon2idPasswordEncoder;
import eu.exeris.kernel.spi.security.credentials.PasswordEncoderConfig;
import eu.exeris.sdk.composition.lifecycle.CapabilityLifecycleHooks;
import eu.exeris.sku.identity.IdentityComposition;
import eu.exeris.sku.identity.IdentityServices;
import eu.exeris.sku.identity.config.IdentityConfig;
import eu.exeris.sku.identity.http.IdentityRoutes;
import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.JdbcTransactionalExecutor;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.RecordingNotificationDispatcher;
import eu.exeris.sku.identity.support.TestConfig;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What the launcher can tell about a failure from the interrupt flag after the composition's own unwind or
 * stop has run on the thread. The launcher classifies a failure as a stop only if it has an interrupt-typed
 * cause and the flag was set before the composition's stop or unwind began; a flag the composition itself
 * deferred does not count. The decision is taken inside the kernel's callback of {@code serve}, which no
 * test can reach without a capability whose drain overruns in a booted kernel, so this class checks the
 * premises the decision stands on: the state the composition leaves on the thread, what the flag-and-cause
 * test alone would answer in that state, and the ending each answer maps to.
 */
@DisplayName("The classification of a failure after the composition has deferred the stop request")
class StopClassificationAfterUnwindTest {

    private static final long BOUND_SECONDS = 60;
    private static final String WATCHDOG = "identity-drain-watchdog";

    private static IdentityComposition base;
    private static Constructor<IdentityComposition> constructor;
    private static ServiceBoundaryCoreModule boundary;

    @BeforeAll
    static void assemble() throws Exception {
        PostgresSupport.Database unused = new PostgresSupport.Database("jdbc:postgresql://127.0.0.1:1/unused", "u", "p",
                "jdbc:postgresql://127.0.0.1:1/unused", "u", "p");
        IdentityConfig config = TestConfig.load();
        boundary = ServiceBoundaryCoreModule.builder().strictRoutes(true).build();
        base = IdentityComposition.builder()
                .config(config)
                .routes(new IdentityRoutes(config))
                .serviceBoundary(boundary)
                .transactionalExecutor(new JdbcTransactionalExecutor(unused))
                .passwordEncoder(new Argon2idPasswordEncoder(new PasswordEncoderConfig(8_192, 1, 1, 32)))
                .notificationDispatcher(new RecordingNotificationDispatcher())
                .membershipDirectory(new InMemoryMembershipDirectory())
                .build();
        constructor = IdentityComposition.class.getDeclaredConstructor(ServiceBoundaryCoreModule.class, List.class,
                eu.exeris.caps.jwt.api.JwtAdmissionPolicy.class, eu.exeris.caps.jwt.api.JwtServiceBoundaryBinding.class,
                IdentityServices.class);
        constructor.setAccessible(true);
    }

    @BeforeEach
    void noWatchdogIsAlive() {
        Thread.interrupted();
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (liveWatchdogs() > 0 && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        assertThat(liveWatchdogs()).as("watchdog threads alive").isZero();
    }

    private static long liveWatchdogs() {
        return Thread.getAllStackTraces().keySet().stream()
                .filter(t -> t.getName().equals(WATCHDOG) && t.isAlive()).count();
    }

    @FunctionalInterface
    private interface Action {
        void run() throws Exception;
    }

    private static final class Cap implements CapabilityLifecycleHooks {
        final String name;
        volatile Action onInitialize = () -> { };
        volatile Action onDrain = () -> { };

        Cap(String name) {
            this.name = name;
        }

        @Override
        public void initialize() throws Exception {
            onInitialize.run();
        }

        @Override
        public void drain(Duration timeout) throws Exception {
            onDrain.run();
        }
    }

    private static final class Fixture {
        final List<Cap> caps = List.of(new Cap("A"), new Cap("B"), new Cap("C"));
        final IdentityComposition composition;

        Fixture() throws Exception {
            composition = constructor.newInstance(boundary, new ArrayList<CapabilityLifecycleHooks>(caps),
                    base.jwtAdmissionPolicy(), base.jwtBinding(), base.services());
        }
    }

    /** What the launcher's thread holds after the call: the failure, the flag, and what the flag-and-cause test says. */
    private record After(Throwable failure, boolean flag, boolean flagAndCauseSayInterrupt, Throwable unexpected) {
    }

    private static After onThread(boolean flagOnEntry, Callable<?> action) throws Exception {
        Object[] box = new Object[4];
        Thread thread = new Thread(() -> {
            if (flagOnEntry) {
                Thread.currentThread().interrupt();
            }
            try {
                action.call();
            } catch (Throwable failure) {
                box[0] = failure;
                box[1] = Thread.currentThread().isInterrupted();
                box[2] = IdentitySkuApplication.causedByInterrupt(failure);
                return;
            }
            box[1] = Thread.currentThread().isInterrupted();
        }, "launcher-thread");
        thread.setDaemon(true);
        thread.start();
        thread.join(TimeUnit.SECONDS.toMillis(BOUND_SECONDS));
        if (thread.isAlive()) {
            thread.interrupt();
            throw new AssertionError("the call did not return within " + BOUND_SECONDS + " s");
        }
        return new After((Throwable) box[0], Boolean.TRUE.equals(box[1]), Boolean.TRUE.equals(box[2]), (Throwable) box[3]);
    }

    private static void overrun() {
        List<Thread> found = Thread.getAllStackTraces().keySet().stream()
                .filter(t -> t.getName().equals(WATCHDOG) && t.isAlive()).toList();
        if (found.size() != 1) {
            throw new AssertionError("expected one watchdog, found " + found.size());
        }
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
        while (found.get(0).isAlive()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("the watchdog did not fire");
            }
            Thread.onSpinWait();
        }
    }

    private static IllegalStateException failureWithAnInterruptCause() {
        return new IllegalStateException("a step refused the interrupt", new InterruptedException("refused"));
    }

    @Test
    @DisplayName("A failed start whose unwind overran, with the flag clear before it began and an InterruptedException in the failure's cause chain: the unwind leaves the flag set, so the flag and the cause alone would call it a stop, and a failure is status 70")
    void unwindThatOverranLeavesAFlagThatWouldMakeAFailureLookLikeAStop() throws Exception {
        Fixture fixture = new Fixture();
        IllegalStateException failure = failureWithAnInterruptCause();
        fixture.caps.get(2).onInitialize = () -> {
            throw failure;
        };
        fixture.caps.get(1).onDrain = StopClassificationAfterUnwindTest::overrun;

        After after = onThread(false, () -> {
            fixture.composition.start();
            return null;
        });

        assertThat(after.failure()).isSameAs(failure);
        assertThat(after.flag()).as("the unwind deferred the watchdog's interrupt").isTrue();
        assertThat(after.flagAndCauseSayInterrupt()).as("the test the launcher guards against reading alone").isTrue();
        assertThat(IdentitySkuApplication.exitStatus(IdentitySkuApplication.Ending.SERVICE_FAILED)).isEqualTo(70);
        assertThat(IdentitySkuApplication.exitStatus(IdentitySkuApplication.Ending.STOPPED)).isZero();
    }

    @Test
    @DisplayName("The same failure with the flag set before the start began: the flag is set on return and the flag and the cause call it a stop, which is status 0")
    void flagSetBeforeTheStartMakesItAStop() throws Exception {
        Fixture fixture = new Fixture();
        IllegalStateException failure = failureWithAnInterruptCause();
        fixture.caps.get(2).onInitialize = () -> {
            throw failure;
        };

        After after = onThread(true, () -> {
            fixture.composition.start();
            return null;
        });

        assertThat(after.failure()).isSameAs(failure);
        assertThat(after.flag()).isTrue();
        assertThat(after.flagAndCauseSayInterrupt()).isTrue();
        assertThat(IdentitySkuApplication.exitStatus(IdentitySkuApplication.Ending.STOPPED)).isZero();
    }

    @Test
    @DisplayName("A teardown failure after a stop that deferred the flag: the stop leaves the flag set although the thread was not interrupted by anyone, and the flag and an interrupt cause alone would call a failure of the teardown a stop")
    void teardownFailureAfterAStopThatDeferredTheFlag() throws Exception {
        Fixture fixture = new Fixture();
        fixture.composition.start();
        fixture.caps.get(2).onDrain = StopClassificationAfterUnwindTest::overrun;
        IllegalStateException teardown = failureWithAnInterruptCause();

        After after = onThread(false, () -> {
            fixture.composition.stop(Duration.ofMillis(250));
            throw teardown;
        });

        assertThat(after.failure()).isSameAs(teardown);
        assertThat(after.flag()).isTrue();
        assertThat(after.flagAndCauseSayInterrupt()).isTrue();
    }

    @Test
    @DisplayName("A failure with no interrupt-typed cause is never a stop, whether the flag is clear, set before, or deferred by an overrunning unwind; a socket timeout is a network failure in every one")
    void failureWithoutAnInterruptCauseIsNeverAStop() throws Exception {
        Throwable[] failures = {
                new IllegalStateException("plain"),
                new IllegalStateException("wrapped", new IOException("io")),
                new IllegalStateException("timeout", new SocketTimeoutException("read timed out"))};
        for (Throwable failure : failures) {
            Fixture overrunning = new Fixture();
            overrunning.caps.get(2).onInitialize = () -> {
                throw (RuntimeException) failure;
            };
            overrunning.caps.get(1).onDrain = StopClassificationAfterUnwindTest::overrun;
            Fixture plain = new Fixture();
            plain.caps.get(2).onInitialize = () -> {
                throw (RuntimeException) failure;
            };

            After clear = onThread(false, () -> {
                Fixture none = new Fixture();
                none.caps.get(2).onInitialize = () -> {
                    throw (RuntimeException) failure;
                };
                none.composition.start();
                return null;
            });
            After set = onThread(true, () -> {
                plain.composition.start();
                return null;
            });
            After deferred = onThread(false, () -> {
                overrunning.composition.start();
                return null;
            });

            assertThat(clear.flagAndCauseSayInterrupt()).as("flag clear, " + failure).isFalse();
            assertThat(set.flagAndCauseSayInterrupt()).as("flag set before, " + failure).isFalse();
            assertThat(deferred.flag()).as("flag deferred, " + failure).isTrue();
            assertThat(deferred.flagAndCauseSayInterrupt()).as("flag deferred, " + failure).isFalse();
        }
    }
}
