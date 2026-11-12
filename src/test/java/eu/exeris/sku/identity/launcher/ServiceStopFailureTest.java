package eu.exeris.sku.identity.launcher;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** What {@link ServiceStop#stop()} hands its caller when an action fails. */
@DisplayName("ServiceStop failures")
class ServiceStopFailureTest {

    @Test
    @DisplayName("A fatal VM error is thrown to the caller that performed the stop, never returned as a failure to report; the stop is complete and a later call returns null")
    void virtualMachineErrorIsThrown() {
        AtomicInteger composed = new AtomicInteger();
        OutOfMemoryError fatal = new OutOfMemoryError("fatal");
        ServiceStop stop = new ServiceStop(() -> {
            throw fatal;
        });
        stop.admit(composed::incrementAndGet);

        assertThatThrownBy(stop::stop).isSameAs(fatal);

        assertThat(composed).as("the composition was still stopped").hasValue(1);
        assertThat(stop.stop()).isNull();
    }

    @Test
    @DisplayName("An Error that is not a VM error is returned to the caller that performed the stop, and only to it")
    void otherErrorIsReturnedOnce() {
        AssertionError failure = new AssertionError("failed");
        ServiceStop stop = new ServiceStop(() -> {
            throw failure;
        });
        stop.admit(() -> { });

        assertThat(stop.stop()).isSameAs(failure);
        assertThat(stop.stop()).isNull();
    }

    @Test
    @DisplayName("The first failure is the one returned; a later one is attached to it")
    void firstFailureWins() {
        IllegalStateException first = new IllegalStateException("withdraw");
        AssertionError second = new AssertionError("composition");
        ServiceStop stop = new ServiceStop(() -> {
            throw first;
        });
        stop.admit(() -> {
            throw second;
        });

        assertThat(stop.stop()).isSameAs(first);
        assertThat(first.getSuppressed()).containsExactly(second);
    }
}
