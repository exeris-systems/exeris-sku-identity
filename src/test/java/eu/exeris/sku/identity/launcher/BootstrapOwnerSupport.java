package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.support.LaunchedProcess;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.TestConfig;
import eu.exeris.sku.identity.support.process.FileMembershipDirectory;
import eu.exeris.sku.identity.support.process.HostFiles;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * What the tests of the {@code bootstrap-owner} command share: the settings under their documented names, a
 * launcher environment for a database, a password file with a chosen mode, a run of the command in a process
 * of its own, and the observations "nothing was created" is made of.
 */
final class BootstrapOwnerSupport {

    static final String EMAIL = "EXERIS_IDENTITY_BOOTSTRAP_OWNER_EMAIL";
    static final String PASSWORD_FILE = "EXERIS_IDENTITY_BOOTSTRAP_OWNER_PASSWORD_FILE";
    static final String TENANT = "EXERIS_IDENTITY_BOOTSTRAP_OWNER_TENANT";
    static final String INLINE_PASSWORD = "EXERIS_IDENTITY_BOOTSTRAP_OWNER_PASSWORD";
    static final String MEMBERSHIPS = "memberships";

    static final int OK = 0;
    static final int USAGE = 64;
    static final int NOT_MIGRATED = 65;
    static final int UNAVAILABLE = 69;
    static final int NOT_COMPLETED = 70;
    static final int ACCOUNTS_EXIST = 73;
    static final int CONFIG = 78;

    private BootstrapOwnerSupport() {
    }

    /** What a process printed and how it ended. */
    record Run(int status, String output) {
    }

    /** A random address that the credential store accepts. */
    static String email() {
        return "owner-" + UUID.randomUUID().toString().substring(0, 12) + "@example.test";
    }

    /** Writes a password file, then sets its mode where the filesystem has modes. */
    static Path passwordFile(Path dir, byte[] content, String permissions) throws IOException {
        Path file = dir.resolve("owner-password-" + UUID.randomUUID().toString().substring(0, 8));
        Files.write(file, content);
        if (Files.getFileStore(file).supportsFileAttributeView("posix")) {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString(permissions));
        }
        return file;
    }

    /** A password file readable by its owner only. */
    static Path passwordFile(Path dir, String content) throws IOException {
        return passwordFile(dir, content.getBytes(StandardCharsets.UTF_8), "rw-------");
    }

    /**
     * A launcher environment for a development service over the database, with the owner's address and
     * password file. No membership directory is configured.
     */
    static Map<String, String> environment(PostgresSupport.Database database, Path passwordFile) throws IOException {
        Map<String, String> env = LaunchedProcess.serviceEnvironment(database, LaunchedProcess.freePort(),
                TestConfig.env());
        env.put("EXERIS_ENVIRONMENT", "development");
        env.put(EMAIL, email());
        env.put(PASSWORD_FILE, passwordFile.toString());
        return env;
    }

    /** Configures the file-backed directory and the tenant the owner role is granted in. */
    static void withDirectory(Map<String, String> env, Path hostDirectory, UUID tenant) {
        env.put("EXERIS_IDENTITY_MEMBERSHIP_DIRECTORY", FileMembershipDirectory.class.getName());
        env.put(HostFiles.DIRECTORY_VARIABLE, hostDirectory.toString());
        env.put(TENANT, tenant.toString());
    }

    /** Runs the command in a JVM of its own and waits for it to end. */
    static Run run(Map<String, String> env, String... arguments) throws Exception {
        String[] command = new String[arguments.length + 1];
        command[0] = "bootstrap-owner";
        System.arraycopy(arguments, 0, command, 1, arguments.length);
        try (LaunchedProcess process = LaunchedProcess.start(env, command)) {
            int status = process.awaitExit(120);
            return new Run(status, process.output());
        }
    }

    /** The number of rows of the credential table, read as the database's owner. */
    static long accounts(PostgresSupport.Database database) throws SQLException {
        try (Connection owner = database.owner(); Statement statement = owner.createStatement();
             ResultSet rows = statement.executeQuery("SELECT count(*) FROM credential_records")) {
            rows.next();
            return rows.getLong(1);
        }
    }

    /** The names of the public tables, read as the database's owner. */
    static List<String> tables(PostgresSupport.Database database) throws SQLException {
        List<String> names = new ArrayList<>();
        try (Connection owner = database.owner(); Statement statement = owner.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename")) {
            while (rows.next()) {
                names.add(rows.getString(1));
            }
        }
        return names;
    }

    /** The grants a file-backed directory recorded; empty when none. */
    static List<String> grants(Path hostDirectory) {
        return HostFiles.lines(hostDirectory, MEMBERSHIPS);
    }

    /** An independent copy of an environment. */
    static Map<String, String> copy(Map<String, String> env) {
        return new HashMap<>(env);
    }

    /** One row of the credential table. */
    record Credential(UUID subject, String loginIdentifier, boolean verified, boolean verifiedAtSet) {
    }

    /** The only row of the credential table. */
    static Credential onlyCredential(PostgresSupport.Database database) throws SQLException {
        try (Connection owner = database.owner(); Statement statement = owner.createStatement();
             ResultSet rows = statement.executeQuery(
                     "SELECT subject_id, login_identifier, email_verified, verified_at IS NOT NULL "
                             + "FROM credential_records")) {
            if (!rows.next()) {
                throw new AssertionError("the credential table is empty");
            }
            Credential only = new Credential(UUID.fromString(rows.getString(1)), rows.getString(2),
                    rows.getBoolean(3), rows.getBoolean(4));
            if (rows.next()) {
                throw new AssertionError("the credential table has more than one row");
            }
            return only;
        }
    }
}
