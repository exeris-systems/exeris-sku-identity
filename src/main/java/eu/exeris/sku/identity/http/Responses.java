package eu.exeris.sku.identity.http;

import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpHeader;
import eu.exeris.kernel.spi.http.HttpResponse;
import eu.exeris.kernel.spi.http.HttpStatus;
import eu.exeris.kernel.spi.http.HttpVersion;
import tools.jackson.databind.json.JsonMapper;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Writes JSON responses. Bodies are serialised from values, never concatenated, and every response forbids
 * caching because it may carry a credential.
 */
final class Responses {

    private final JsonMapper mapper;
    private final Cors cors;

    Responses(JsonMapper mapper, Cors cors) {
        this.mapper = mapper;
        this.cors = cors;
    }

    /** An object with the given name and value pairs, in order. */
    static Map<String, Object> object(Object... pairs) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            result.put((String) pairs[i], pairs[i + 1]);
        }
        return result;
    }

    void json(HttpExchange exchange, HttpStatus status, Object body) {
        byte[] bytes = mapper.writeValueAsBytes(body);
        List<HttpHeader> headers = baseHeaders(exchange);
        headers.add(new HttpHeader("Content-Type", "application/json"));
        headers.add(new HttpHeader("Content-Length", String.valueOf(bytes.length)));
        exchange.respond(new HttpResponse(status, HttpVersion.HTTP_1_1, headers, new ByteArrayLoanedBuffer(bytes)));
    }

    void noContent(HttpExchange exchange) {
        exchange.respond(HttpResponse.noBody(HttpStatus.NO_CONTENT, HttpVersion.HTTP_1_1, baseHeaders(exchange)));
    }

    void problem(HttpExchange exchange, Problem problem) {
        json(exchange, problem.status(), object("error", problem.code()));
    }

    private List<HttpHeader> baseHeaders(HttpExchange exchange) {
        List<HttpHeader> headers = new ArrayList<>();
        headers.add(new HttpHeader("Cache-Control", "no-store"));
        headers.add(new HttpHeader("Pragma", "no-cache"));
        headers.add(new HttpHeader("X-Content-Type-Options", "nosniff"));
        headers.addAll(cors.responseHeaders(exchange));
        return headers;
    }
}
