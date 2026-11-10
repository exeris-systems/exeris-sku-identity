package eu.exeris.sku.identity.launcher;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Reads launcher settings from environment variables and records every problem instead of stopping at the
 * first, so that one refusal names everything an operator has to fix.
 */
final class LauncherEnvironment {

    private final Map<String, String> env;
    private final List<String> problems = new ArrayList<>();

    LauncherEnvironment(Map<String, String> env) {
        this.env = env;
    }

    List<String> problems() {
        return problems;
    }

    void problem(String sentence) {
        problems.add(sentence);
    }

    /** The trimmed value, or null when the variable is unset or blank. */
    String optional(String key) {
        String value = env.get(key);
        return value == null || value.isBlank() ? null : value.trim();
    }

    /** The trimmed value; a missing one is recorded as a problem and null is returned. */
    String required(String key) {
        String value = optional(key);
        if (value == null) {
            problems.add(key + " is not set.");
        }
        return value;
    }

    /**
     * A secret given either inline under {@code key} or as the path of a file under {@code key + "_FILE"}.
     * Exactly one must be set, and a file must be a readable regular file with content.
     */
    String secret(String key) {
        String inline = env.get(key);
        String file = optional(key + "_FILE");
        boolean hasInline = inline != null && !inline.isEmpty();
        if (hasInline && file != null) {
            problems.add("Only one of " + key + " and " + key + "_FILE may be set.");
            return null;
        }
        if (hasInline) {
            return inline;
        }
        if (file == null) {
            problems.add("One of " + key + " and " + key + "_FILE must be set.");
            return null;
        }
        Path path = Path.of(file);
        if (!Files.isRegularFile(path) || !Files.isReadable(path)) {
            problems.add(key + "_FILE does not name a readable file.");
            return null;
        }
        try {
            String content = Files.readString(path);
            int end = content.length();
            while (end > 0 && (content.charAt(end - 1) == '\n' || content.charAt(end - 1) == '\r')) {
                end--;
            }
            if (end == 0) {
                problems.add(key + "_FILE names an empty file.");
                return null;
            }
            return content.substring(0, end);
        } catch (IOException e) {
            problems.add(key + "_FILE cannot be read.");
            return null;
        }
    }

    /** An integer within bounds; the default when unset. A bad value is recorded and the default returned. */
    int integer(String key, int defaultValue, int min, int max) {
        String value = optional(key);
        if (value == null) {
            return defaultValue;
        }
        try {
            int parsed = Integer.parseInt(value);
            if (parsed < min || parsed > max) {
                problems.add(key + " must be between " + min + " and " + max + ".");
                return defaultValue;
            }
            return parsed;
        } catch (NumberFormatException e) {
            problems.add(key + " must be a whole number.");
            return defaultValue;
        }
    }
}
