package eu.exeris.sku.identity.launcher;

import eu.exeris.caps.credentialstore.api.model.PasswordPolicy;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.Set;

/**
 * Reads the first account's password from a file. The content goes from the file's bytes to a character
 * array and nowhere else: no {@code String} holds it, and every intermediate buffer is zeroed before this
 * class returns, whether it succeeds or not. A message about a refused file names the setting and the rule,
 * never the content.
 */
final class PasswordFile {

    private static final System.Logger LOG = System.getLogger(PasswordFile.class.getName());
    private static final Set<PosixFilePermission> FORBIDDEN = Set.of(
            PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_WRITE, PosixFilePermission.GROUP_EXECUTE,
            PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_WRITE, PosixFilePermission.OTHERS_EXECUTE);

    private PasswordFile() {
    }

    /**
     * Reads the password.
     *
     * <p>The file is a regular, readable file (links are followed, because mounted secrets are links). On a
     * filesystem that reports POSIX permissions it must be accessible by its owner only; elsewhere the
     * permissions cannot be checked and a warning says so. Strict UTF-8 is required, trailing line breaks
     * are removed, and the length must lie in the policy's window.
     *
     * @param file   the file named by {@link BootstrapOwnerSettings#PASSWORD_FILE}
     * @param policy the password policy of the credential store
     * @param in     records the problem when the file is unusable
     * @return the password, to be zeroed by the caller; null when a problem was recorded
     */
    static char[] read(Path file, PasswordPolicy policy, LauncherEnvironment in) {
        String key = BootstrapOwnerSettings.PASSWORD_FILE;
        if (!Files.isRegularFile(file) || !Files.isReadable(file)) {
            in.problem(key + " does not name a readable regular file.");
            return null;
        }
        PosixFileAttributeView posix = Files.getFileAttributeView(file, PosixFileAttributeView.class);
        try {
            if (posix != null) {
                Set<PosixFilePermission> granted = posix.readAttributes().permissions();
                if (granted.stream().anyMatch(FORBIDDEN::contains)) {
                    in.problem(key + " names a file that others can access: restrict it to its owner (mode 0400 "
                            + "or 0600).");
                    return null;
                }
            } else {
                LOG.log(System.Logger.Level.WARNING, "The permissions of the file named by {0} cannot be checked "
                        + "on this filesystem; keep it readable by its owner only", key);
            }
            long limit = (long) policy.maxLength() * 4 + 2;
            if (Files.size(file) > limit) {
                in.problem(key + " names a file larger than a password of at most " + policy.maxLength()
                        + " characters can be.");
                return null;
            }
            return decode(file, policy, in, key);
        } catch (IOException e) {
            in.problem(key + " cannot be read.");
            return null;
        }
    }

    private static char[] decode(Path file, PasswordPolicy policy, LauncherEnvironment in, String key)
            throws IOException {
        byte[] bytes = Files.readAllBytes(file);
        char[] chars = new char[bytes.length];
        try {
            CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            CharBuffer out = CharBuffer.wrap(chars);
            CoderResult decoded = decoder.decode(ByteBuffer.wrap(bytes), out, true);
            if (decoded.isError() || !decoder.flush(out).isUnderflow()) {
                in.problem(key + " names a file that is not valid UTF-8.");
                return null;
            }
            int end = out.position();
            while (end > 0 && (chars[end - 1] == '\n' || chars[end - 1] == '\r')) {
                end--;
            }
            if (end == 0) {
                in.problem(key + " names an empty file.");
                return null;
            }
            if (end < policy.minLength() || end > policy.maxLength()) {
                in.problem(key + " names a file whose content must be between " + policy.minLength() + " and "
                        + policy.maxLength() + " characters long.");
                return null;
            }
            return Arrays.copyOf(chars, end);
        } finally {
            Arrays.fill(bytes, (byte) 0);
            Arrays.fill(chars, '\0');
        }
    }
}
