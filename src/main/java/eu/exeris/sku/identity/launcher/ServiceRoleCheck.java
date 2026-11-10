package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.config.IdentityConfigException;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Row-level security only isolates tenants from a role that cannot step around it. The service refuses
 * to run as a superuser or as a role that bypasses row-level security.
 */
final class ServiceRoleCheck {

    private ServiceRoleCheck() {
    }

    /**
     * @param database the service role's database
     * @throws IdentityConfigException when the role is a superuser or bypasses row-level security
     * @throws SQLException            when the database cannot be reached
     */
    static void verify(DatabaseSettings database) throws SQLException {
        try (Connection connection = database.open();
             Statement statement = connection.createStatement();
             ResultSet row = statement.executeQuery(
                     "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")) {
            if (!row.next()) {
                throw new IdentityConfigException("The role in " + StartupPlan.DATABASE_PREFIX
                        + "_USER cannot be inspected.");
            }
            if (row.getBoolean(1) || row.getBoolean(2)) {
                throw new IdentityConfigException("The role in " + StartupPlan.DATABASE_PREFIX
                        + "_USER must be NOSUPERUSER and NOBYPASSRLS: tenant isolation depends on row-level "
                        + "security applying to it.");
            }
        }
    }
}
