package eu.exeris.sku.identity.launcher;

import eu.exeris.kernel.spi.http.HttpHandler;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpResponse;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.sku.identity.support.TestExchange;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("SwitchableHandler")
class SwitchableHandlerTest {

    private static final long BOUND_SECONDS = 10;

    /** A handler that answers 200 and counts the requests it saw. */
    private static final class Counting implements HttpHandler {

        final AtomicInteger seen = new AtomicInteger();

        @Override
        public void handle(eu.exeris.kernel.spi.http.HttpExchange exchange) {
            seen.incrementAndGet();
            exchange.respond(HttpResponse.noBody(HttpStatus.OK, exchange.request().version()));
        }
    }

    private static int answer(SwitchableHandler handler) {
        TestExchange exchange = TestExchange.of(HttpMethod.GET, "/health");
        handler.handle(exchange);
        return exchange.code();
    }

    @Test
    @DisplayName("Before a handler is set every request is answered 503")
    void unavailableBeforeServe() {
        assertThat(answer(new SwitchableHandler())).isEqualTo(503);
    }

    @Test
    @DisplayName("After serve the requests are delegated")
    void delegatesAfterServe() {
        SwitchableHandler handler = new SwitchableHandler();
        Counting target = new Counting();

        handler.serve(target);

        assertThat(answer(handler)).isEqualTo(200);
        assertThat(target.seen).hasValue(1);
    }

    @Test
    @DisplayName("After withdraw the requests are answered 503 and are not delegated")
    void unavailableAfterWithdraw() {
        SwitchableHandler handler = new SwitchableHandler();
        Counting target = new Counting();
        handler.serve(target);

        handler.withdraw();

        assertThat(answer(handler)).isEqualTo(503);
        assertThat(target.seen).hasValue(0);
    }

    @Test
    @DisplayName("A serve after a withdrawal has no effect, however often it is repeated, and withdraw is idempotent")
    void withdrawalIsFinal() {
        SwitchableHandler handler = new SwitchableHandler();
        Counting target = new Counting();

        handler.withdraw();
        handler.withdraw();
        handler.serve(target);
        handler.serve(target);

        assertThat(answer(handler)).isEqualTo(503);
        assertThat(target.seen).hasValue(0);
    }

    @Test
    @DisplayName("A serve replaces the handler set before it, while the switch is not withdrawn")
    void serveReplaces() {
        SwitchableHandler handler = new SwitchableHandler();
        Counting first = new Counting();
        Counting second = new Counting();

        handler.serve(first);
        handler.serve(second);
        answer(handler);

        assertThat(first.seen).hasValue(0);
        assertThat(second.seen).hasValue(1);
    }

    /**
     * Both calls are released from one latch so that they contend; whichever wins, the withdrawal is final,
     * so the switch ends withdrawn.
     */
    @RepeatedTest(200)
    @DisplayName("serve and withdraw called concurrently from two threads end withdrawn")
    void concurrentServeAndWithdrawEndWithdrawn() throws Exception {
        SwitchableHandler handler = new SwitchableHandler();
        Counting target = new Counting();
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch go = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<?> serving = pool.submit(() -> {
                ready.countDown();
                await(go);
                handler.serve(target);
            });
            Future<?> withdrawing = pool.submit(() -> {
                ready.countDown();
                await(go);
                handler.withdraw();
            });
            assertThat(ready.await(BOUND_SECONDS, TimeUnit.SECONDS)).isTrue();
            go.countDown();
            serving.get(BOUND_SECONDS, TimeUnit.SECONDS);
            withdrawing.get(BOUND_SECONDS, TimeUnit.SECONDS);
        } finally {
            pool.shutdownNow();
        }

        assertThat(answer(handler)).isEqualTo(503);
        assertThat(target.seen).hasValue(0);
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
