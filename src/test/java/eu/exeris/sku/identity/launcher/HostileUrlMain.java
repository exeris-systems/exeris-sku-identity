package eu.exeris.sku.identity.launcher;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

/**
 * Runs {@link DatabaseSettings#open()} against the real PostgreSQL driver for each URL of a file, in a JVM of
 * its own, and reports per URL whether the driver was called. A recording driver is registered ahead of the
 * real one and counts every connection attempt for a {@code jdbc:postgresql:} URL before handing it on. The
 * URLs are never passed through {@code ForeignLogs}: what reaches the output is what the launcher's URL rule
 * and the driver leave.
 *
 * <p>Each line of the file is {@code id TAB url}. For each URL the output has a line
 * {@code RESULT id reached=<calls> state=<SQLSTATE> class=<exception class>} and nothing derived from the URL.
 * An id that starts with {@code DIRECT} bypasses the launcher and calls the driver, as a control. The second
 * and third arguments, when given, are the role and the password the connection is opened with.
 */
public final class HostileUrlMain {

    private static final AtomicInteger CALLS = new AtomicInteger();

    private HostileUrlMain() {
    }

    /** Counts the attempts to connect and delegates to the driver that was registered first. */
    private static final class Recording implements Driver {
        private final Driver real;

        Recording(Driver real) {
            this.real = real;
        }

        @Override
        public Connection connect(String url, Properties info) throws SQLException {
            if (url == null || !url.startsWith("jdbc:postgresql:")) {
                return null;
            }
            CALLS.incrementAndGet();
            return real.connect(url, info);
        }

        @Override
        public boolean acceptsURL(String url) {
            return url != null && url.startsWith("jdbc:postgresql:");
        }

        @Override
        public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) throws SQLException {
            return real.getPropertyInfo(url, info);
        }

        @Override
        public int getMajorVersion() {
            return real.getMajorVersion();
        }

        @Override
        public int getMinorVersion() {
            return real.getMinorVersion();
        }

        @Override
        public boolean jdbcCompliant() {
            return false;
        }

        @Override
        public Logger getParentLogger() throws SQLFeatureNotSupportedException {
            return real.getParentLogger();
        }
    }

    public static void main(String[] arguments) throws Exception {
        List<Driver> registered = Collections.list(DriverManager.getDrivers());
        Driver real = null;
        for (Driver driver : registered) {
            if (driver instanceof org.postgresql.Driver) {
                real = driver;
            }
            DriverManager.deregisterDriver(driver);
        }
        if (real == null) {
            System.out.println("NO-REAL-DRIVER");
            System.exit(2);
        }
        DriverManager.registerDriver(new Recording(real));
        DriverManager.registerDriver(real);
        String user = arguments.length > 1 ? arguments[1] : "svc";
        String password = arguments.length > 2 ? arguments[2] : "pw";
        List<String> lines = new ArrayList<>(Files.readAllLines(Path.of(arguments[0])));
        for (String line : lines) {
            int tab = line.indexOf('\t');
            String id = line.substring(0, tab);
            String url = line.substring(tab + 1);
            int before = CALLS.get();
            String state = "none";
            String type = "none";
            try (Connection connection = id.startsWith("DIRECT")
                    ? DriverManager.getConnection(url, user, password)
                    : new DatabaseSettings(url, user, password).open()) {
                state = "connected";
            } catch (SQLException e) {
                state = String.valueOf(e.getSQLState());
                type = e.getClass().getName();
            } catch (RuntimeException e) {
                type = e.getClass().getName();
            }
            System.out.println("RESULT " + id + " reached=" + (CALLS.get() - before) + " state=" + state + " class=" + type);
            System.out.flush();
        }
        System.out.println("DONE");
        System.exit(0);
    }
}
