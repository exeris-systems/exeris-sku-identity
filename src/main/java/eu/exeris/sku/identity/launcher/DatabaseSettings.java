package eu.exeris.sku.identity.launcher;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * How to reach one PostgreSQL database as one role. The password never appears in the text form.
 *
 * @param url      a {@code jdbc:postgresql:} URL
 * @param user     the role to connect as
 * @param password the role's password
 */
record DatabaseSettings(String url, String user, String password) {

    private static final String SCHEME = "jdbc:postgresql:";

    /**
     * Reads {@code <prefix>_URL}, {@code <prefix>_USER} and {@code <prefix>_PASSWORD(_FILE)}.
     *
     * @return the settings, or null when any is missing or unusable; the problems are recorded
     */
    static DatabaseSettings read(LauncherEnvironment in, String prefix) {
        String url = in.required(prefix + "_URL");
        String user = in.required(prefix + "_USER");
        String password = in.secret(prefix + "_PASSWORD");
        if (url != null && !url.startsWith(SCHEME)) {
            in.problem(prefix + "_URL must be a " + SCHEME + " URL.");
            return null;
        }
        if (url == null || user == null || password == null) {
            return null;
        }
        return new DatabaseSettings(url, user, password);
    }

    Connection open() throws SQLException {
        return DriverManager.getConnection(url, user, password);
    }

    @Override
    public String toString() {
        return "DatabaseSettings[url=" + url + ", user=" + user + ", password=<withheld>]";
    }
}
