package eu.exeris.sku.identity.http;

import eu.exeris.kernel.spi.memory.LoanedBuffer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Production classes and kernel buffers")
class NoHandWrittenBuffersTest {

    private static Path classesRoot() throws URISyntaxException {
        return Path.of(Responses.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    }

    @Test
    @DisplayName("no compiled class of the service is a LoanedBuffer")
    void noCompiledImplementation() throws IOException, URISyntaxException {
        Path root = classesRoot();
        List<String> offenders = new ArrayList<>();
        int inspected = 0;
        try (Stream<Path> files = Files.walk(root)) {
            for (Path file : files.filter(f -> f.toString().endsWith(".class")).toList()) {
                String relative = root.relativize(file).toString();
                if (relative.equals("module-info.class") || relative.startsWith("META-INF")) {
                    continue;
                }
                String name = relative.substring(0, relative.length() - ".class".length()).replace('/', '.');
                inspected++;
                try {
                    Class<?> type = Class.forName(name, false, Responses.class.getClassLoader());
                    if (LoanedBuffer.class.isAssignableFrom(type)) {
                        offenders.add(name);
                    }
                } catch (ClassNotFoundException | LinkageError unloadable) {
                    // a class whose optional dependency is absent cannot implement the buffer either
                }
            }
        }
        assertThat(inspected).isGreaterThan(20);
        assertThat(offenders).isEmpty();
    }

    @Test
    @DisplayName("no source of the service names a LoanedBuffer implementation or its base class")
    void noSourceImplementation() throws IOException {
        Path sources = Path.of("src", "main", "java");
        List<String> offenders = new ArrayList<>();
        try (Stream<Path> files = Files.walk(sources)) {
            for (Path file : files.filter(f -> f.toString().endsWith(".java")).toList()) {
                String text = Files.readString(file);
                if (text.matches("(?s).*(implements|extends)[^{;]*(LoanedBuffer|AbstractLoanedBuffer).*")
                        || text.contains("ByteArrayLoanedBuffer") || text.contains("HeapLoanedBuffer")) {
                    offenders.add(file.toString());
                }
            }
        }
        assertThat(offenders).isEmpty();
    }
}
