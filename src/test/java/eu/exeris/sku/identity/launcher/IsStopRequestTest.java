package eu.exeris.sku.identity.launcher;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.nio.channels.ClosedByInterruptException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link IdentitySkuApplication#isStopRequest} as a table: the failure is a stop only when the flag may not be
 * the composition's own deferred one, the flag is set, and the cause chain holds an
 * {@code InterruptedException}, a {@code ClosedByInterruptException} or an {@code InterruptedIOException} of
 * exactly that class. The table crosses both booleans with every kind of cause at several depths and inside a
 * cyclic chain, and a source check keeps the classification in one method.
 */
@DisplayName("IdentitySkuApplication.isStopRequest: when a failure is a stop")
class IsStopRequestTest {

    private static final Path APPLICATION = Path.of("src", "main", "java", "eu", "exeris", "sku", "identity",
            "launcher", "IdentitySkuApplication.java");
    private static final Path MAIN = Path.of("src", "main", "java");

    /** A subclass of {@code InterruptedIOException} that is raised for a cause other than an interrupt. */
    private static final class LocalTimeout extends InterruptedIOException {
        private static final long serialVersionUID = 1L;

        LocalTimeout() {
            super("a timeout of its own");
        }
    }

    private enum Kind {
        NONE(false) {
            @Override
            Throwable make() {
                return null;
            }
        },
        INTERRUPTED(true) {
            @Override
            Throwable make() {
                return new InterruptedException("interrupted");
            }
        },
        CLOSED_BY_INTERRUPT(true) {
            @Override
            Throwable make() {
                return new ClosedByInterruptException();
            }
        },
        EXACT_INTERRUPTED_IO(true) {
            @Override
            Throwable make() {
                return new InterruptedIOException("interrupted io");
            }
        },
        SOCKET_TIMEOUT(false) {
            @Override
            Throwable make() {
                return new SocketTimeoutException("timed out");
            }
        },
        LOCAL_SUBCLASS(false) {
            @Override
            Throwable make() {
                return new LocalTimeout();
            }
        };

        final boolean isAStop;

        Kind(boolean isAStop) {
            this.isAStop = isAStop;
        }

        abstract Throwable make();
    }

    private enum Shape { DEPTH_0, DEPTH_1, DEPTH_3, CYCLIC }

    /** A failure whose chain holds {@code cause} at the given depth, or, with no cause, a chain of that length. */
    private static Throwable chain(Kind kind, Shape shape) {
        Throwable cause = kind.make();
        switch (shape) {
            case DEPTH_0:
                return cause != null ? cause : new IllegalStateException("no cause");
            case DEPTH_1:
                return new IllegalStateException("wrapper", cause);
            case DEPTH_3:
                return new IllegalStateException("outer", new RuntimeException("middle",
                        new IllegalArgumentException("inner", cause)));
            default:
                IllegalStateException head = new IllegalStateException("head");
                Throwable tail = cause != null ? cause : new RuntimeException("tail");
                head.initCause(tail);
                tail.initCause(head);
                return head;
        }
    }

    static Stream<Arguments> table() {
        List<Arguments> rows = new ArrayList<>();
        for (boolean deferred : new boolean[] {false, true}) {
            for (boolean flagSet : new boolean[] {false, true}) {
                for (Kind kind : Kind.values()) {
                    for (Shape shape : Shape.values()) {
                        rows.add(Arguments.of(deferred, flagSet, kind, shape));
                    }
                }
            }
        }
        return rows.stream();
    }

    @ParameterizedTest(name = "deferred={0} flagSet={1} cause={2} {3}")
    @MethodSource("table")
    @DisplayName("1. A stop exactly when the flag may not be deferred, is set, and the chain holds an interrupt of an exact class")
    void theTable(boolean deferred, boolean flagSet, Kind kind, Shape shape) {
        Throwable failure = chain(kind, shape);

        boolean expected = !deferred && flagSet && kind.isAStop;

        assertThat(IdentitySkuApplication.isStopRequest(failure, deferred, flagSet)).isEqualTo(expected);
    }

    @Test
    @DisplayName("2. No failure is not a stop, whatever the flag says")
    void nullFailure() {
        for (boolean deferred : new boolean[] {false, true}) {
            for (boolean flagSet : new boolean[] {false, true}) {
                assertThat(IdentitySkuApplication.isStopRequest(null, deferred, flagSet))
                        .as("deferred=" + deferred + " flagSet=" + flagSet).isFalse();
            }
        }
    }

    @Test
    @DisplayName("3. An interrupt below a timeout that is a subclass is still found, and the subclass alone is not")
    void aSubclassDoesNotHideAnInterruptBelowIt() {
        Throwable below = new IllegalStateException("outer", new LocalTimeout());
        below.getCause().initCause(new InterruptedException("below"));

        assertThat(IdentitySkuApplication.isStopRequest(below, false, true)).isTrue();
        assertThat(IdentitySkuApplication.isStopRequest(new IllegalStateException(new LocalTimeout()), false, true))
                .isFalse();
    }

    @Test
    @DisplayName("4. causedByInterrupt is isStopRequest with a flag that is never deferred, read from the thread")
    void causedByInterruptReadsTheThread() throws Exception {
        Throwable failure = new IllegalStateException(new InterruptedException("x"));
        boolean[] seen = new boolean[2];
        Thread thread = new Thread(() -> {
            seen[0] = IdentitySkuApplication.causedByInterrupt(failure);
            Thread.currentThread().interrupt();
            seen[1] = IdentitySkuApplication.causedByInterrupt(failure);
        });
        thread.start();
        thread.join();

        assertThat(seen).containsExactly(false, true);
    }

    /** Where the launcher decides that a failure is a stop. */
    @Nested
    @DisplayName("The classification lives in one method")
    class OneDecisionPoint {

        private String code(Path file) throws IOException {
            StringBuilder code = new StringBuilder();
            for (String line : Files.readAllLines(file)) {
                String trimmed = line.trim();
                if (!trimmed.startsWith("*") && !trimmed.startsWith("//") && !trimmed.startsWith("/*")) {
                    code.append(line).append('\n');
                }
            }
            return code.toString();
        }

        private List<Path> sources() throws IOException {
            try (Stream<Path> files = Files.walk(MAIN)) {
                return files.filter(p -> p.toString().endsWith(".java")).toList();
            }
        }

        @Test
        @DisplayName("Only the listed lines declare or call isStopRequest and causedByInterrupt")
        void callSitesAreTheListedOnes() throws IOException {
            List<String> found = new ArrayList<>();
            for (Path file : sources()) {
                for (String line : code(file).split("\n")) {
                    if (line.contains("isStopRequest(") || line.contains("causedByInterrupt(")) {
                        found.add(MAIN.relativize(file).getFileName() + ": " + line.trim());
                    }
                }
            }

            assertThat(found).containsExactlyInAnyOrder(
                    "IdentitySkuApplication.java: static boolean causedByInterrupt(Throwable failure) {",
                    "IdentitySkuApplication.java: return isStopRequest(failure, false, interrupted());",
                    "IdentitySkuApplication.java: static boolean isStopRequest(Throwable failure, boolean "
                            + "flagMayBeDeferred, boolean flagSet) {",
                    "IdentitySkuApplication.java: if (isStopRequest(e, outcome.flagMayBeDeferred, interrupted())) {",
                    "IdentitySkuApplication.java: if (!isStopRequest(e, outcome.flagMayBeDeferred, interrupted())) {");
        }

        @Test
        @DisplayName("No other place in the launcher tests a failure's class for an interrupt")
        void noOtherPlaceClassifiesByType() throws IOException {
            String code = code(APPLICATION);
            int start = code.indexOf("static boolean isStopRequest(");
            int end = code.indexOf("\n    }\n", start);
            assertThat(start).isPositive();
            assertThat(end).isGreaterThan(start);
            String outside = code.substring(0, start) + code.substring(end);

            assertThat(outside).doesNotContainPattern("instanceof\\s+(java\\.[\\w.]+\\.)?"
                    + "(InterruptedException|ClosedByInterruptException|InterruptedIOException)");
            assertThat(outside).doesNotContain("InterruptedIOException.class");
            for (Path file : sources()) {
                if (file.getFileName().toString().equals("IdentitySkuApplication.java")) {
                    continue;
                }
                assertThat(code(file)).as(file.toString()).doesNotContainPattern("instanceof\\s+(java\\.[\\w.]+\\.)?"
                        + "(InterruptedException|ClosedByInterruptException|InterruptedIOException)");
            }
        }

        @Test
        @DisplayName("The Javadoc and the code state the same three conditions")
        void javadocStatesTheConditions() throws IOException {
            String source = Files.readString(APPLICATION).replaceAll("\\s*\\n\\s*\\*?\\s*", " ");

            assertThat(source).contains("It is a stop only when the interrupt flag is set, the flag is not possibly "
                    + "the composition's own deferred one, and the failure has an interrupt-typed cause");
            assertThat(source).contains("if (flagMayBeDeferred || !flagSet) { return false; }");
            assertThat(source).contains("cause.getClass() == java.io.InterruptedIOException.class");
        }
    }
}
