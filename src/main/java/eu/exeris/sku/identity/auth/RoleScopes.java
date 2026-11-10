package eu.exeris.sku.identity.auth;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The fixed mapping from a tenant role to the scopes an access token carries, and the rule that picks
 * the tenant a token is issued for.
 *
 * <p>A token names at most one active tenant. A subject with exactly one membership gets that tenant and
 * its role; a subject with none or several gets a token that names no tenant and carries no role, because
 * there is nothing to choose between. Self-service routes need only an authenticated token.
 */
public final class RoleScopes {

    /** Role that owns a tenant. */
    public static final String OWNER = "owner";
    /** Role that administers a tenant. */
    public static final String ADMIN = "admin";

    /** The role of the host's own operators; it is never granted or issued by this service. */
    public static final String PLATFORM_ADMIN = "platform-admin";

    private static final Pattern WELL_FORMED = Pattern.compile("[a-z][a-z0-9-]{0,31}");

    private RoleScopes() {
    }

    /**
     * The scopes a role is granted.
     *
     * @param role a tenant role
     * @return the scopes; empty for a role that administers nothing
     */
    public static Set<String> scopesOf(String role) {
        return mayAdminister(role) ? Set.of(Scopes.INVITATIONS_WRITE) : Set.of();
    }

    /**
     * Whether the role may administer its tenant's invitations.
     *
     * @param role a tenant role
     * @return true for {@link #OWNER} and {@link #ADMIN}
     */
    public static boolean mayAdminister(String role) {
        return OWNER.equals(role) || ADMIN.equals(role);
    }

    /**
     * Whether a role is one this service knows and may issue, grant or invite into: lower-case letters,
     * digits and hyphens, starting with a letter, at most 32 characters, and not the platform role. The
     * platform role belongs to the host and is never issued, however it is written: it is compared after
     * trimming and lower-casing. A role that is not exactly in the known form, such as one with capitals
     * or surrounding blanks, is unknown and never reaches a token.
     *
     * @param role a tenant role; may be null
     * @return true when a token may carry the role
     */
    public static boolean issuable(String role) {
        if (role == null || !WELL_FORMED.matcher(role).matches()) {
            return false;
        }
        return !PLATFORM_ADMIN.equals(role.strip().toLowerCase(Locale.ROOT));
    }

    /**
     * The membership a token is issued for.
     *
     * @param memberships the memberships of the subject that a token may carry
     * @return the only membership; empty when the subject has none or several
     */
    public static Optional<Membership> activeMembership(List<Membership> memberships) {
        return memberships != null && memberships.size() == 1 ? Optional.of(memberships.get(0)) : Optional.empty();
    }
}
