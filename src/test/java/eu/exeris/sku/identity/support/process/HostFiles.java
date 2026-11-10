package eu.exeris.sku.identity.support.process;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;

/**
 * The files the host doubles of a launched service share with the test that launched it: an outbox, a
 * membership table and a row-level-security probe log, all in the directory named by
 * {@value #DIRECTORY_VARIABLE}.
 */
public final class HostFiles {

    /** The variable naming the directory the doubles write in. */
    public static final String DIRECTORY_VARIABLE = "IDENTITY_TEST_HOST_DIR";

    private HostFiles() {
    }

    /** The directory of the running process, from its environment. */
    static Path directory() {
        String directory = System.getenv(DIRECTORY_VARIABLE);
        if (directory == null || directory.isBlank()) {
            throw new IllegalStateException(DIRECTORY_VARIABLE + " is not set");
        }
        return Path.of(directory);
    }

    /** Appends one line to a file of the directory. */
    static synchronized void append(String file, String line) {
        try {
            Files.writeString(directory().resolve(file), line + System.lineSeparator(), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Every line of a file of the directory; empty when the file does not exist. */
    public static synchronized List<String> lines(Path directory, String file) {
        Path path = directory.resolve(file);
        try {
            return Files.exists(path) ? Files.readAllLines(path, StandardCharsets.UTF_8) : List.of();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
