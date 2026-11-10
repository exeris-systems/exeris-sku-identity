package eu.exeris.sku.identity.support;

import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpRequest;
import eu.exeris.kernel.spi.http.HttpResponse;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.http.HttpTypedResponse;
import eu.exeris.kernel.spi.http.HttpVersion;
import eu.exeris.kernel.spi.memory.AllocationHint;
import eu.exeris.kernel.spi.memory.LoanedBuffer;
import eu.exeris.kernel.spi.memory.MemoryAllocator;
import tools.jackson.databind.json.JsonMapper;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * A hand-written exchange that behaves like the engine's: it answers once and rejects a second answer
 * without touching its body, takes ownership of the response body, copies the bytes it is told about and
 * releases the buffer exactly once, and encodes a typed response into a buffer of the allocator it was built
 * with. Request bodies live in allocator buffers that are released when the exchange is answered.
 */
public final class TestExchange implements HttpExchange {

    /** How the exchange treats the answer it is given. */
    public enum Mode {
        /** Accepts the answer, writes it and releases the body. */
        NORMAL,
        /** Accepts the answer, releases the body and then fails, as an engine whose write failed does. */
        FAIL_AFTER_RELEASE
    }

    private static final JsonMapper ENCODER = JsonMapper.builder().build();
    private static final TrackingAllocator SHARED = TrackingAllocator.create();

    private final HttpRequest request;
    private final MemoryAllocator allocator;
    private Mode mode = Mode.NORMAL;
    private String remoteAddress = "198.51.100.7";
    private boolean answered;
    private HttpStatus status;
    private HttpVersion responseVersion;
    private List<HttpHeader> responseHeaders = List.of();
    private HttpTypedResponse typedResponse;
    private boolean bodyPresent;
    private byte[] responseBytes = new byte[0];

    private TestExchange(HttpRequest request, MemoryAllocator allocator) {
        this.request = request;
        this.allocator = allocator;
    }

    /** The allocator exchanges use unless they are built with another. */
    public static TrackingAllocator sharedAllocator() {
        return SHARED;
    }

    /** A request without a body. */
    public static TestExchange of(HttpMethod method, String path, HttpHeader... headers) {
        return of(HttpVersion.HTTP_1_1, method, path, headers);
    }

    /** A request without a body, on the given protocol version. */
    public static TestExchange of(HttpVersion version, HttpMethod method, String path, HttpHeader... headers) {
        return new TestExchange(HttpRequest.noBody(method, path, version, List.of(headers)), SHARED);
    }

    /** A request with a JSON body. */
    public static TestExchange json(HttpMethod method, String path, String body, HttpHeader... headers) {
        return withBody(method, path, body, "application/json", headers);
    }

    /** A request with a body of the given media type. */
    public static TestExchange withBody(HttpMethod method, String path, String body, String contentType,
                                        HttpHeader... headers) {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        List<HttpHeader> all = new ArrayList<>(List.of(headers));
        all.add(new HttpHeader("Content-Type", contentType));
        all.add(new HttpHeader("Content-Length", String.valueOf(bytes.length)));
        return new TestExchange(new HttpRequest(method, null, path, HttpVersion.HTTP_1_1, all, buffer(SHARED, bytes)),
                SHARED);
    }

    /** The same request answered through the given allocator instead of the shared one. */
    public TestExchange using(MemoryAllocator other) {
        return new TestExchange(request, other).from(remoteAddress).mode(mode);
    }

    /** Sets the peer address the exchange reports. */
    public TestExchange from(String address) {
        this.remoteAddress = address;
        return this;
    }

    /** Sets how the exchange treats the answer. */
    public TestExchange mode(Mode mode) {
        this.mode = mode;
        return this;
    }

    private static LoanedBuffer buffer(MemoryAllocator allocator, byte[] bytes) {
        // allocateNetwork rejects an empty estimate, and a request may carry an empty body
        LoanedBuffer buffer = bytes.length == 0
                ? allocator.allocate(AllocationHint.MICRO) : allocator.allocateNetwork(bytes.length);
        MemorySegment.copy(bytes, 0, buffer.segment(), ValueLayout.JAVA_BYTE, 0L, bytes.length);
        buffer.setSize(bytes.length);
        return buffer;
    }

    @Override
    public HttpRequest request() {
        return request;
    }

    @Override
    public String remoteAddress() {
        return remoteAddress;
    }

    /** Respond-once: a second answer throws before it touches anything it is given. */
    private void claim() {
        if (answered) {
            throw new IllegalStateException("the exchange was already answered");
        }
        answered = true;
    }

    @Override
    public void respond(HttpResponse response) {
        claim();
        deliver(response);
    }

    @Override
    public void respond(HttpTypedResponse response) {
        claim();
        this.typedResponse = response;
        byte[] encoded = ENCODER.writeValueAsBytes(response.payload());
        List<HttpHeader> headers = new ArrayList<>(response.headers());
        headers.add(new HttpHeader("Content-Type", "application/json"));
        deliver(new HttpResponse(response.status(), request.version(), headers, buffer(allocator, encoded)));
    }

    private void deliver(HttpResponse response) {
        LoanedBuffer body = response.body();
        try (body) {
            this.status = response.status();
            this.responseVersion = response.version();
            List<HttpHeader> headers = new ArrayList<>(response.headers());
            if (body != null) {
                this.bodyPresent = true;
                this.responseBytes = body.segment().asSlice(0, body.size()).toArray(ValueLayout.JAVA_BYTE);
            }
            if (headers.stream().noneMatch(h -> h.nameEqualsIgnoreCase("Content-Length"))) {
                headers.add(new HttpHeader("Content-Length", String.valueOf(responseBytes.length)));
            }
            this.responseHeaders = headers;
        } finally {
            if (request.body() != null) {
                request.body().close();
            }
        }
        if (mode == Mode.FAIL_AFTER_RELEASE) {
            throw new IllegalStateException("the write failed");
        }
    }

    /** The status the exchange was answered with, or null when it was not answered. */
    public HttpStatus status() {
        return status;
    }

    /** The status code, or 0 when the exchange was not answered. */
    public int code() {
        return status == null ? 0 : status.code();
    }

    /** The protocol version the answer was written on, or null when it was not answered. */
    public HttpVersion responseVersion() {
        return responseVersion;
    }

    /** The typed response the handler gave, or null when it answered another way. */
    public HttpTypedResponse typedResponse() {
        return typedResponse;
    }

    /** Whether the answer carried a body buffer. */
    public boolean hadBody() {
        return bodyPresent;
    }

    /** The bytes of the response body; empty when there was none. */
    public byte[] bodyBytes() {
        return responseBytes.clone();
    }

    /** The response body as text; empty when there was none. */
    public String body() {
        return new String(responseBytes, StandardCharsets.UTF_8);
    }

    /** The response headers as written, with the length the engine would add. */
    public List<HttpHeader> headers() {
        return responseHeaders;
    }

    /** The value of a response header, or null. */
    public String header(String name) {
        return responseHeaders.stream().filter(h -> h.nameEqualsIgnoreCase(name))
                .map(HttpHeader::value).findFirst().orElse(null);
    }
}
