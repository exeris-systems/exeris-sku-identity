package eu.exeris.sku.identity.http;

import eu.exeris.kernel.spi.http.HttpExchange;
import eu.exeris.kernel.spi.http.HttpRequest;
import eu.exeris.kernel.spi.memory.LoanedBuffer;
import tools.jackson.core.JacksonException;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.lang.foreign.ValueLayout;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Reads request bodies as JSON objects with a fixed set of fields.
 *
 * <p>A body is read only when it is declared {@code application/json}, which a cross-origin form post cannot
 * be, and only up to {@link #MAX_BYTES}. A field the route does not name, a repeated field, a second value
 * after the object and a field of the wrong type are all refused, so a request cannot carry a subject or a
 * tenant the route does not take from the caller's credentials.
 */
final class JsonBodies {

    /** The largest body any route accepts. */
    static final int MAX_BYTES = 16 * 1024;

    private final JsonMapper mapper;

    JsonBodies(JsonMapper mapper) {
        this.mapper = mapper;
    }

    /** A mapper that refuses duplicate fields and trailing content. */
    static JsonMapper mapper() {
        return JsonMapper.builder()
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .build();
    }

    /**
     * Reads the body as an object whose fields are among the allowed ones.
     *
     * @param exchange the request
     * @param allowed  every field name the route accepts
     * @return the fields
     * @throws Problem.Failure when the body is absent, too large, not JSON or carries other fields
     */
    Fields read(HttpExchange exchange, Set<String> allowed) {
        HttpRequest request = exchange.request();
        String contentType = request.firstHeader("Content-Type").orElse("").trim().toLowerCase(Locale.ROOT);
        if (!(contentType.equals("application/json") || contentType.startsWith("application/json;"))) {
            throw Problem.UNSUPPORTED_MEDIA_TYPE.raise();
        }
        if (declaredLength(request) > MAX_BYTES) {
            throw Problem.REQUEST_TOO_LARGE.raise();
        }
        LoanedBuffer body = request.body();
        if (body == null || body.size() == 0) {
            throw Problem.INVALID_REQUEST.raise();
        }
        if (body.size() > MAX_BYTES) {
            throw Problem.REQUEST_TOO_LARGE.raise();
        }
        byte[] bytes = body.segment().asSlice(0, body.size()).toArray(ValueLayout.JAVA_BYTE);
        JsonNode root;
        try {
            root = mapper.readTree(bytes);
        } catch (JacksonException e) {
            throw Problem.INVALID_REQUEST.raise();
        }
        if (root == null || !root.isObject()) {
            throw Problem.INVALID_REQUEST.raise();
        }
        for (String name : root.propertyNames()) {
            if (!allowed.contains(name)) {
                throw Problem.INVALID_REQUEST.raise();
            }
        }
        return new Fields(root);
    }

    /**
     * Like {@link #read}, but a request without a body is an object with no fields.
     *
     * @param exchange the request
     * @param allowed  every field name the route accepts
     * @return the fields; none when the request has no body
     */
    Fields readOptional(HttpExchange exchange, Set<String> allowed) {
        return hasContent(exchange.request()) ? read(exchange, allowed) : Fields.EMPTY;
    }

    /**
     * Refuses a request that carries a body, for a route that takes none.
     *
     * @param exchange the request
     */
    void requireEmpty(HttpExchange exchange) {
        if (hasContent(exchange.request())) {
            throw Problem.INVALID_REQUEST.raise();
        }
    }

    private static boolean hasContent(HttpRequest request) {
        LoanedBuffer body = request.body();
        return (body != null && body.size() > 0) || declaredLength(request) > 0;
    }

    private static long declaredLength(HttpRequest request) {
        Optional<String> value = request.firstHeader("Content-Length");
        if (value.isEmpty()) {
            return 0;
        }
        try {
            return Long.parseLong(value.get().trim());
        } catch (NumberFormatException e) {
            throw Problem.INVALID_REQUEST.raise();
        }
    }

    /** The typed fields of a body. */
    static final class Fields {

        private static final int MAX_PASSWORD_CHARS = 1_024;
        private static final Fields EMPTY = new Fields(JsonMapper.shared().createObjectNode());

        private final JsonNode node;

        private Fields(JsonNode node) {
            this.node = node;
        }

        boolean has(String name) {
            JsonNode value = node.get(name);
            return value != null && !value.isNull();
        }

        /** A required, non-blank string of at most {@code maxLength} characters. */
        String string(String name, int maxLength) {
            return optionalString(name, maxLength).orElseThrow(Problem.INVALID_REQUEST::raise);
        }

        /** An optional string; absent and null are alike. */
        Optional<String> optionalString(String name, int maxLength) {
            JsonNode value = node.get(name);
            if (value == null || value.isNull()) {
                return Optional.empty();
            }
            if (!value.isString()) {
                throw Problem.INVALID_REQUEST.raise();
            }
            String text = value.stringValue();
            if (text.isBlank() || text.length() > maxLength) {
                throw Problem.INVALID_REQUEST.raise();
            }
            return Optional.of(text);
        }

        /** A required identifier. */
        UUID uuid(String name) {
            try {
                return UUID.fromString(string(name, 36));
            } catch (IllegalArgumentException e) {
                throw Problem.INVALID_REQUEST.raise();
            }
        }

        /** A required password; the caller wipes the array. */
        char[] password(String name) {
            JsonNode value = node.get(name);
            if (value == null || !value.isString()) {
                throw Problem.INVALID_REQUEST.raise();
            }
            String text = value.stringValue();
            if (text.isEmpty() || text.length() > MAX_PASSWORD_CHARS) {
                throw Problem.INVALID_REQUEST.raise();
            }
            return text.toCharArray();
        }

        /** An optional whole number in range. */
        Optional<Long> optionalLong(String name, long min, long max) {
            JsonNode value = node.get(name);
            if (value == null || value.isNull()) {
                return Optional.empty();
            }
            if (!value.isIntegralNumber() || !value.canConvertToLong()) {
                throw Problem.INVALID_REQUEST.raise();
            }
            long number = value.longValue();
            if (number < min || number > max) {
                throw Problem.INVALID_REQUEST.raise();
            }
            return Optional.of(number);
        }
    }
}
