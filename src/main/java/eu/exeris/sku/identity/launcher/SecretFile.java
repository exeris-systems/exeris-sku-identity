package eu.exeris.sku.identity.launcher;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The one reader of a file that holds a secret as its content. The configuration uses it to obtain a
 * password and the log redaction uses it to learn the same password, so that what the service connects with
 * is exactly what the log withholds: the same bound, the same strict UTF-8 decoding, the same removal of the trailing
 * line break.
 */
final class SecretFile {

    /** Largest file read as a secret, in bytes; a larger file is a configuration refusal, never a secret. */
    static final long MAXIMUM_BYTES = 1024 * 1024L;

    private SecretFile() {
    }

    /** Why a file did not yield a secret. */
    enum Refusal {
        /** Not a readable regular file. */
        NOT_READABLE,
        /** Larger than {@link #MAXIMUM_BYTES}. */
        TOO_LARGE,
        /** Nothing but line breaks. */
        EMPTY,
        /** The read failed. */
        UNREADABLE
    }

    /**
     * The outcome of a read: exactly one of the content and the refusal is present.
     *
     * @param content the content without its trailing line breaks
     * @param refusal why there is no content
     */
    record Read(String content, Refusal refusal) {
    }

    /**
     * Reads the file.
     *
     * @param file the file
     * @return its content with trailing {@code \n} and {@code \r} removed, or the reason it is no secret;
     *         never throws
     */
    static Read read(Path file) {
        try {
            if (!Files.isRegularFile(file) || !Files.isReadable(file)) {
                return new Read(null, Refusal.NOT_READABLE);
            }
            if (Files.size(file) > MAXIMUM_BYTES) {
                return new Read(null, Refusal.TOO_LARGE);
            }
            String content = Files.readString(file);
            int end = content.length();
            while (end > 0 && (content.charAt(end - 1) == '\n' || content.charAt(end - 1) == '\r')) {
                end--;
            }
            return end == 0 ? new Read(null, Refusal.EMPTY) : new Read(content.substring(0, end), null);
        } catch (IOException | RuntimeException unreadable) {
            return new Read(null, Refusal.UNREADABLE);
        }
    }
}
