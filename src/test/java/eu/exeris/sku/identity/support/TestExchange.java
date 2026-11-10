package eu.exeris.sku.identity.support;

import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpRequest;
import eu.exeris.kernel.spi.http.HttpResponse;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.http.HttpVersion;
import eu.exeris.sku.identity.http.ByteArrayLoanedBuffer;

import java.lang.foreign.ValueLayout;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** A hand-written exchange that records what it is answered with. */
public final class TestExchange implements HttpExchange {

    private final HttpRequest request;
    private String remoteAddress = "198.51.100.7";
    private HttpStatus status;
    private List<HttpHeader> responseHeaders = List.of();
    private String responseBody = "";

    private TestExchange(HttpRequest request) {
        this.request = request;
    }

    /** A request without a body. */
    public static TestExchange of(HttpMethod method, String path, HttpHeader... headers) {
        return new TestExchange(HttpRequest.noBody(method, path, HttpVersion.HTTP_1_1, List.of(headers)));
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
        return new TestExchange(new HttpRequest(method, null, path, HttpVersion.HTTP_1_1, all,
                new ByteArrayLoanedBuffer(bytes)));
    }

    /** Sets the peer address the exchange reports. */
    public TestExchange from(String address) {
        this.remoteAddress = address;
        return this;
    }

    @Override
    public HttpRequest request() {
        return request;
    }

    @Override
    public String remoteAddress() {
        return remoteAddress;
    }

    @Override
    public void respond(HttpResponse response) {
        this.status = response.status();
        this.responseHeaders = response.headers();
        if (response.body() != null && response.body().size() > 0) {
            this.responseBody = new String(
                    response.body().segment().asSlice(0, response.body().size()).toArray(ValueLayout.JAVA_BYTE),
                    StandardCharsets.UTF_8);
        }
    }

    @Override
    public void respond(HttpStatus status) {
        this.status = status;
    }

    /** The status the exchange was answered with, or null when it was not answered. */
    public HttpStatus status() {
        return status;
    }

    /** The status code, or 0 when the exchange was not answered. */
    public int code() {
        return status == null ? 0 : status.code();
    }

    /** The response body as text; empty when there was none. */
    public String body() {
        return responseBody;
    }

    /** The value of a response header, or null. */
    public String header(String name) {
        return responseHeaders.stream().filter(h -> h.nameEqualsIgnoreCase(name))
                .map(HttpHeader::value).findFirst().orElse(null);
    }
}
