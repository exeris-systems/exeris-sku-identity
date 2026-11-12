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
    /** SQLSTATE of a connection that could not be established. */
    private static final String REFUSED_URL_STATE = "08001";

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

    /**
     * Opens a connection. The driver is called only with a URL that {@link JdbcUrl} accepts, because the
     * driver writes the URLs it cannot parse to the log. A refused URL is the connection failure SQLSTATE
     * {@value #REFUSED_URL_STATE}, as if the driver had refused it, with a message that names no part of it.
     *
     * @return the connection
     * @throws SQLException when the URL is refused or the database cannot be used
     */
    Connection open() throws SQLException {
        if (!JdbcUrl.acceptable(url)) {
            throw new SQLException("The database URL is not a jdbc:postgresql://host[:port]/database URL without "
                    + "credentials: the user and the password are separate settings.", REFUSED_URL_STATE);
        }
        return DriverManager.getConnection(url, user, password);
    }

    @Override
    public String toString() {
        return "DatabaseSettings[url=" + url + ", user=" + user + ", password=<withheld>]";
    }
}
