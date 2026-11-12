package eu.exeris.sku.identity.launcher;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * The one way the launcher writes a line that carries text it did not write itself: an exception's message,
 * a driver's SQLSTATE, a configuration problem. Every such text passes through {@link LogRedaction#of} with
 * the secrets the command is configured with before it reaches the logger, so a new log line cannot skip the
 * redaction by being written another way. A line made only of the launcher's own constants, or of a class
 * name, is logged directly.
 */
final class LauncherLog {

    private LauncherLog() {
    }

    /**
     * Logs a line whose arguments are foreign text.
     *
     * @param logger  the logger of the caller
     * @param level   the level
     * @param format  the launcher's own constant format; argument {@code {i}} is {@code foreign[i]}
     * @param secrets the values that must never appear, see {@link #secrets}
     * @param foreign the texts that did not originate in the launcher; each is redacted, a {@code null} one
     *                is logged as {@code (no message)}
     */
    static void log(System.Logger logger, System.Logger.Level level, String format, String[] secrets,
                    String... foreign) {
        Object[] arguments = new Object[foreign.length];
        for (int i = 0; i < foreign.length; i++) {
            arguments[i] = LogRedaction.of(foreign[i], secrets);
        }
        logger.log(level, format, arguments);
    }

    /**
     * The database passwords the environment configures under the given prefixes, read the way the
     * launcher reads them ({@code <prefix>_PASSWORD}, or the content of the file named by
     * {@code <prefix>_PASSWORD_FILE}) but without recording a problem and without ever throwing, so that the
     * secrets are known even when the configuration itself is what failed.
     *
     * @param environment the process environment
     * @param prefixes    the database setting prefixes, for example {@code EXERIS_DATABASE}
     * @return the secrets found; empty when none is configured or readable
     */
    static String[] secrets(Map<String, String> environment, String... prefixes) {
        List<String> found = new ArrayList<>();
        for (String prefix : prefixes) {
            try {
                String inline = environment.get(prefix + "_PASSWORD");
                if (inline != null && !inline.isEmpty()) {
                    found.add(inline);
                }
                String file = environment.get(prefix + "_PASSWORD_FILE");
                if (file != null && !file.isBlank()) {
                    String content = contentOf(Path.of(file.trim()));
                    if (content != null) {
                        found.add(content);
                    }
                }
            } catch (RuntimeException unreadable) { // NOPMD - a secret that cannot be read cannot be named
                // nothing to add for this prefix
            }
        }
        return found.toArray(String[]::new);
    }

    /** The secrets of the plan's service database. */
    static String[] secrets(DatabaseSettings database) {
        return database == null ? new String[0] : new String[]{database.password()};
    }

    /**
     * The given secrets and the content of a password held in a character array. The array is copied into a
     * {@code String} that cannot be zeroed, so this is called only on the path that is about to log a
     * failure, never ahead of it.
     */
    static String[] with(String[] secrets, char[] password) {
        if (password == null || password.length == 0) {
            return secrets;
        }
        String[] all = Arrays.copyOf(secrets, secrets.length + 1);
        all[secrets.length] = new String(password);
        return all;
    }

    private static String contentOf(Path file) {
        return SecretFile.read(file).content();
    }
}
