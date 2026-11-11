package eu.exeris.sku.identity.launcher;

import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.UUID;

/**
 * What the {@code bootstrap-owner} command is told: the first account's address, the file that holds its
 * password and, when the host has a membership directory, the tenant that account owns.
 *
 * <p>The password is never a setting: it is read from the file only, so it appears in no argument, no
 * environment value and no process listing.
 *
 * @param email        the address of the account
 * @param passwordFile the file holding the password
 * @param tenantId     the tenant to grant the owner role in; null exactly when no directory is configured
 */
record BootstrapOwnerSettings(String email, Path passwordFile, UUID tenantId) {

    static final String EMAIL = "EXERIS_IDENTITY_BOOTSTRAP_OWNER_EMAIL";
    static final String PASSWORD_FILE = "EXERIS_IDENTITY_BOOTSTRAP_OWNER_PASSWORD_FILE";
    static final String TENANT = "EXERIS_IDENTITY_BOOTSTRAP_OWNER_TENANT";
    /** Never accepted: any non-empty value is refused so that a password is not left in the environment. */
    static final String INLINE_PASSWORD = "EXERIS_IDENTITY_BOOTSTRAP_OWNER_PASSWORD";

    private static final int MAX_ADDRESS_LENGTH = 320;

    /**
     * Reads and checks the settings; every problem is recorded in {@code in}.
     *
     * @param in                  the environment reader
     * @param directoryConfigured whether the host named a membership directory
     * @return the settings, or null when any is missing or unusable
     */
    static BootstrapOwnerSettings read(LauncherEnvironment in, boolean directoryConfigured) {
        int before = in.problems().size();
        String email = in.required(EMAIL);
        if (email != null && email.length() > MAX_ADDRESS_LENGTH) {
            in.problem(EMAIL + " is longer than " + MAX_ADDRESS_LENGTH + " characters.");
        }
        String file = in.required(PASSWORD_FILE);
        Path path = null;
        if (file != null) {
            try {
                path = Path.of(file);
            } catch (InvalidPathException e) {
                in.problem(PASSWORD_FILE + " is not a usable path.");
            }
        }
        if (in.isSet(INLINE_PASSWORD)) {
            in.problem(INLINE_PASSWORD + " must not be set: the password is read only from the file named by "
                    + PASSWORD_FILE + ".");
        }
        UUID tenant = null;
        String tenantText = in.optional(TENANT);
        if (directoryConfigured) {
            if (tenantText == null) {
                in.problem(TENANT + " is not set: it names the tenant the owner role is granted in.");
            }
        } else if (tenantText != null) {
            in.problem(TENANT + " must not be set: no membership directory is configured, so no tenant can be "
                    + "granted.");
            tenantText = null;
        }
        if (tenantText != null) {
            try {
                tenant = UUID.fromString(tenantText);
            } catch (IllegalArgumentException e) {
                in.problem(TENANT + " must be a UUID.");
            }
        }
        if (in.problems().size() != before) {
            return null;
        }
        return new BootstrapOwnerSettings(email, path, tenant);
    }

    @Override
    public String toString() {
        return "BootstrapOwnerSettings[passwordFile=" + passwordFile + ", tenantId=" + tenantId + "]";
    }
}
