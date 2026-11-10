# Runtime image for exeris-sku-identity. Build the jar first (mvn package): the composed capabilities are
# not on Maven Central, so the image is assembled from the built artefact and its target/lib directory
# rather than built inside Docker.
FROM eclipse-temurin:25-jre-alpine

WORKDIR /app

RUN apk add --no-cache wget \
    && addgroup -g 1000 exeris \
    && adduser -D -u 1000 -G exeris -s /bin/sh exeris \
    && chown -R exeris:exeris /app

COPY --chown=exeris:exeris target/exeris-sku-identity-0.1.0-SNAPSHOT.jar app.jar
COPY --chown=exeris:exeris target/lib/ lib/

USER exeris

# The service binds loopback unless told otherwise, which a container cannot be reached on.
ENV EXERIS_HTTP_BIND_HOST=0.0.0.0

# The ingress port (EXERIS_HTTP_PORT).
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:8080/health || exit 1

# JVM options are the operator's: set JAVA_OPTS. No collector or heap size is baked in, because no
# workload-profiling pass has been run for this SKU. Native access is what the kernel's off-heap memory needs.
# The default command serves; `migrate` applies the schema with the privileged database settings.
ENV JAVA_OPTS=""

ENTRYPOINT ["sh", "-c", "exec java --enable-native-access=ALL-UNNAMED $JAVA_OPTS -jar app.jar \"$@\"", "--"]
CMD ["serve"]
