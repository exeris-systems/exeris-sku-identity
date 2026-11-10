package eu.exeris.sku.identity.support;

import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.kernel.spi.http.HttpRequest;
import eu.exeris.kernel.spi.http.HttpResponse;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.http.HttpVersion;

import java.util.List;

/** A hand-written exchange that records the status it is answered with. */
public final class TestExchange implements HttpExchange {

    private final HttpRequest request;
    private HttpStatus status;

    private TestExchange(HttpRequest request) {
        this.request = request;
    }

    /** A request without a body. */
    public static TestExchange of(HttpMethod method, String path, HttpHeader... headers) {
        return new TestExchange(HttpRequest.noBody(method, path, HttpVersion.HTTP_1_1, List.of(headers)));
    }

    @Override
    public HttpRequest request() {
        return request;
    }

    @Override
    public void respond(HttpResponse response) {
        this.status = response.status();
    }

    @Override
    public void respond(HttpStatus status) {
        this.status = status;
    }

    /** The status the exchange was answered with, or null when it was not answered. */
    public HttpStatus status() {
        return status;
    }
}
