package eu.exeris.sku.identity.http;

import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpRequest;
import eu.exeris.kernel.spi.http.HttpResponse;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.http.HttpTypedResponse;
import eu.exeris.kernel.spi.http.HttpVersion;
import eu.exeris.kernel.spi.context.KernelProviders;
import eu.exeris.sku.identity.support.TestExchange;
import eu.exeris.sku.identity.support.TrackingAllocator;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.lang.management.ManagementFactory;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * What the identity routes hand to the kernel: the value to encode, the request's protocol version, headers
 * the kernel completes itself, no buffer of their own, and no ownership claim on a buffer that is not theirs.
 */
@DisplayName("Responses handed to the kernel")
class ResponseHandoffTest {

    private static final String ORIGIN = "https://app.example.test";
    private static final Set<String> KERNEL_OWNED = Set.of("content-length", "content-type");

    private static TrackingAllocator allocator;
    private final Responses responses = new Responses(Cors.of(List.of()));

    @BeforeAll
    static void allocator() {
        allocator = TrackingAllocator.create();
    }

    @AfterAll
    static void closeAllocator() {
        allocator.close();
    }

    private static TestExchange request(HttpVersion version) {
        return TestExchange.of(version, HttpMethod.POST, "/api/v1/auth/login").using(allocator);
    }

    private static List<String> headerNames(List<HttpHeader> headers) {
        return headers.stream().map(h -> h.name().toLowerCase()).toList();
    }

    @Test
    @DisplayName("a JSON answer is a typed response with the status, the value and the hardening headers")
    void typedResponse() {
        TestExchange exchange = request(HttpVersion.HTTP_1_1);

        responses.json(exchange, HttpStatus.CREATED, Responses.object("id", "abc", "n", 3));

        HttpTypedResponse typed = exchange.typedResponse();
        assertThat(typed).isNotNull();
        assertThat(typed.status()).isEqualTo(HttpStatus.CREATED);
        assertThat(typed.payload()).isEqualTo(Map.of("id", "abc", "n", 3));
        assertThat(headerNames(typed.headers())).contains("cache-control", "pragma", "x-content-type-options");
        assertThat(exchange.header("Cache-Control")).isEqualTo("no-store");
    }

    @Test
    @DisplayName("the bytes the engine writes are the JSON of the value, and Content-Length is their count")
    void bytesAndLength() {
        TestExchange exchange = request(HttpVersion.HTTP_1_1);

        responses.json(exchange, HttpStatus.OK, Responses.object("status", "UP", "text", "zażółć"));

        byte[] bytes = exchange.bodyBytes();
        assertThat(exchange.body()).isEqualTo("{\"status\":\"UP\",\"text\":\"zażółć\"}");
        assertThat(exchange.header("Content-Length")).isEqualTo(String.valueOf(bytes.length));
    }

    @Test
    @DisplayName("the application sets neither Content-Length nor Content-Type, the kernel does, once each")
    void kernelOwnedHeaders() {
        TestExchange exchange = request(HttpVersion.HTTP_1_1);

        responses.json(exchange, HttpStatus.OK, Responses.object("a", "b"));
        TestExchange problem = request(HttpVersion.HTTP_1_1);
        responses.problem(problem, Problem.INVALID_REQUEST);

        for (TestExchange answered : List.of(exchange, problem)) {
            assertThat(headerNames(answered.typedResponse().headers())).doesNotContainAnyElementsOf(KERNEL_OWNED);
            assertThat(headerNames(answered.headers()).stream().filter("content-length"::equals)).hasSize(1);
            assertThat(headerNames(answered.headers()).stream().filter("content-type"::equals)).hasSize(1);
        }
    }

    @ParameterizedTest
    @EnumSource(value = HttpVersion.class, names = {"HTTP_1_1", "HTTP_2"})
    @DisplayName("every kind of answer is written on the protocol version of the request")
    void versionIsTheRequests(HttpVersion version) {
        TestExchange json = request(version);
        TestExchange problem = request(version);
        TestExchange noContent = request(version);

        responses.json(json, HttpStatus.OK, Responses.object("k", "v"));
        responses.problem(problem, Problem.INVALID_CREDENTIALS);
        responses.noContent(noContent);

        assertThat(json.responseVersion()).isEqualTo(version);
        assertThat(problem.responseVersion()).isEqualTo(version);
        assertThat(noContent.responseVersion()).isEqualTo(version);
    }

    @Test
    @DisplayName("a problem is the stable code under its status and nothing else")
    void problemBody() {
        TestExchange exchange = request(HttpVersion.HTTP_1_1);

        responses.problem(exchange, Problem.INVALID_CREDENTIALS);

        assertThat(exchange.code()).isEqualTo(401);
        assertThat(exchange.body()).isEqualTo("{\"error\":\"invalid_credentials\"}");
    }

    @Test
    @DisplayName("an answer without a body passes no buffer, allocates nothing and claims no length but zero")
    void emptyBody() {
        long before = allocator.allocations();
        TestExchange exchange = request(HttpVersion.HTTP_1_1);

        responses.noContent(exchange);

        assertThat(exchange.code()).isEqualTo(204);
        assertThat(exchange.hadBody()).isFalse();
        assertThat(allocator.allocations()).isEqualTo(before);
        assertThat(exchange.header("Content-Length")).isEqualTo("0");
        assertThat(exchange.typedResponse()).isNull();
    }

    @Test
    @DisplayName("the routes allocate no buffer: the only one per bodied answer is the one the engine encodes into, released once")
    void oneBufferReleasedOnce() {
        long before = allocator.allocations();
        long released = allocator.finalReleases();

        for (int i = 0; i < 25; i++) {
            responses.json(request(HttpVersion.HTTP_2), HttpStatus.OK, Responses.object("i", i));
        }

        assertThat(allocator.allocations() - before).isEqualTo(25);
        assertThat(allocator.finalReleases() - released).isEqualTo(25);
        assertThat(allocator.outstanding()).isZero();
        assertThat(allocator.closeCalls()).allMatch(calls -> calls == 1);
    }

    @Test
    @DisplayName("an answer given twice is rejected without a second buffer and the first is released once")
    void secondAnswerRejected() {
        long before = allocator.allocations();
        TestExchange exchange = request(HttpVersion.HTTP_1_1);
        responses.json(exchange, HttpStatus.OK, Responses.object("first", true));

        assertThatThrownBy(() -> responses.json(exchange, HttpStatus.OK, Responses.object("second", true)))
                .isInstanceOf(IllegalStateException.class);

        assertThat(exchange.body()).isEqualTo("{\"first\":true}");
        assertThat(allocator.allocations() - before).isEqualTo(1);
        assertThat(allocator.outstanding()).isZero();
        assertThat(allocator.closeCalls()).allMatch(calls -> calls == 1);
    }

    @Test
    @DisplayName("a write that fails after the engine released the body reaches the caller and leaves nothing to release")
    void failureAfterRelease() {
        TestExchange exchange = request(HttpVersion.HTTP_1_1).mode(TestExchange.Mode.FAIL_AFTER_RELEASE);
        long before = allocator.allocations();

        assertThatThrownBy(() -> responses.json(exchange, HttpStatus.OK, Responses.object("a", 1)))
                .isInstanceOf(IllegalStateException.class).hasMessage("the write failed");

        assertThat(allocator.allocations() - before).isEqualTo(1);
        assertThat(allocator.outstanding()).isZero();
        assertThat(allocator.closeCalls()).allMatch(calls -> calls == 1);
    }

    @Test
    @DisplayName("after many answers and a collection no buffer is leaked and every allocation was released")
    void noLeaks() {
        for (int i = 0; i < 200; i++) {
            responses.json(request(i % 2 == 0 ? HttpVersion.HTTP_1_1 : HttpVersion.HTTP_2), HttpStatus.OK,
                    Responses.object("i", i));
            responses.problem(request(HttpVersion.HTTP_1_1), Problem.INVALID_REQUEST);
            responses.noContent(request(HttpVersion.HTTP_1_1));
        }
        System.gc();

        assertThat(allocator.stats().leakCount()).isZero();
        assertThat(allocator.stats().releaseCount()).isEqualTo(allocator.stats().allocationCount());
        assertThat(allocator.outstanding()).isZero();
    }

    @Test
    @DisplayName("the routes need no allocator binding of their own: answering outside any kernel scope works")
    void noAllocatorSlotNeeded() {
        assertThat(KernelProviders.MEMORY_ALLOCATOR.isBound()).isFalse();
        TestExchange exchange = request(HttpVersion.HTTP_1_1);

        responses.json(exchange, HttpStatus.OK, Responses.object("a", "b"));

        assertThat(exchange.code()).isEqualTo(200);
    }

    @Test
    @DisplayName("a large answer costs less than its own size in allocation: the body is never built as a byte array")
    void noBodySizedArray() {
        String large = "x".repeat(256 * 1024);
        Map<String, Object> payload = Responses.object("blob", large);
        CapturingExchange exchange = new CapturingExchange();
        com.sun.management.ThreadMXBean threads =
                (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
        for (int i = 0; i < 3000; i++) {
            responses.json(new CapturingExchange(), HttpStatus.OK, payload);
        }

        int iterations = 1000;
        long start = threads.getCurrentThreadAllocatedBytes();
        for (int i = 0; i < iterations; i++) {
            responses.json(exchange, HttpStatus.OK, payload);
            exchange.reset();
        }
        long perAnswer = (threads.getCurrentThreadAllocatedBytes() - start) / iterations;

        assertThat(perAnswer).as("bytes allocated per answer").isLessThan(4096);
    }

    @Test
    @DisplayName("a preflight answer is written on the protocol version of the request")
    void preflightVersion() {
        Cors cors = Cors.of(List.of(ORIGIN));
        for (HttpVersion version : List.of(HttpVersion.HTTP_1_1, HttpVersion.HTTP_2)) {
            TestExchange exchange = TestExchange.of(version, HttpMethod.OPTIONS, "/api/v1/auth/login",
                    new HttpHeader("Origin", ORIGIN),
                    new HttpHeader("Access-Control-Request-Method", "POST"),
                    new HttpHeader("Access-Control-Request-Headers", "content-type")).using(allocator);

            cors.preflight(exchange);

            assertThat(exchange.code()).isEqualTo(204);
            assertThat(exchange.hadBody()).isFalse();
            assertThat(exchange.header("Content-Length")).isEqualTo("0");
            assertThat(exchange.responseVersion()).as("version of a preflight answer to a %s request", version)
                    .isEqualTo(version);
        }
    }

    /** Records a typed answer without encoding it. */
    private static final class CapturingExchange implements HttpExchange {

        private final HttpRequest request = HttpRequest.noBody(HttpMethod.GET, "/health", HttpVersion.HTTP_1_1,
                List.of());
        private boolean answered;

        void reset() {
            answered = false;
        }

        @Override
        public HttpRequest request() {
            return request;
        }

        @Override
        public void respond(HttpResponse response) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void respond(HttpTypedResponse response) {
            if (answered) {
                throw new IllegalStateException();
            }
            answered = true;
        }
    }
}
