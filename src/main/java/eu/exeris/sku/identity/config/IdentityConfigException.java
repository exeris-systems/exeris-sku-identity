package eu.exeris.sku.identity.config;

import java.util.List;

/**
 * The identity configuration is missing a required value or carries a value that cannot be used.
 *
 * <p>Raised while the configuration is read, before the kernel starts. It carries every problem found,
 * not only the first, so an operator corrects the whole configuration in one pass.
 */
public final class IdentityConfigException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final List<String> problems;

    /**
     * Creates the exception for the problems found.
     *
     * @param problems one sentence per problem, each naming the setting; never empty
     */
    public IdentityConfigException(List<String> problems) {
        super(describe(problems));
        this.problems = List.copyOf(problems);
    }

    /**
     * Creates the exception for a single problem.
     *
     * @param problem a sentence that names the setting
     */
    public IdentityConfigException(String problem) {
        this(List.of(problem));
    }

    /** Every problem found, in the order the settings are read. */
    public List<String> problems() {
        return problems;
    }

    private static String describe(List<String> problems) {
        if (problems.isEmpty()) {
            throw new IllegalArgumentException("problems must not be empty");
        }
        StringBuilder text = new StringBuilder(problems.size() == 1
                ? "1 configuration problem:"
                : problems.size() + " configuration problems:");
        for (String problem : problems) {
            text.append("\n - ").append(problem);
        }
        return text.toString();
    }
}
