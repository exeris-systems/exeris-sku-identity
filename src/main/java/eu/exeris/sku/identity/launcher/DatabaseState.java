package eu.exeris.sku.identity.launcher;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * What a command that creates the first account needs to know about the database before it boots anything:
 * whether the credential store's table is there for the service role to use, and whether it holds any
 * account. It reads as the service role, in autocommit, and changes nothing.
 */
final class DatabaseState {

    /** What the service role finds. */
    enum State {
        /** The credential table is missing, or the role may not read and write it. */
        NOT_MIGRATED,
        /** The table is usable and holds no account. */
        EMPTY,
        /** The table holds at least one account. */
        HAS_ACCOUNTS
    }

    private DatabaseState() {
    }

    /**
     * @param database the service role's database
     * @return the state found
     * @throws SQLException when the database cannot be reached or refuses the read
     */
    static State inspect(DatabaseSettings database) throws SQLException {
        try (Connection connection = database.open();
             Statement statement = connection.createStatement()) {
            boolean usable;
            try (ResultSet row = statement.executeQuery(
                    "SELECT to_regclass('public.credential_records') IS NOT NULL")) {
                usable = row.next() && row.getBoolean(1);
            }
            if (usable) {
                try (ResultSet row = statement.executeQuery(
                        "SELECT has_table_privilege(current_user, 'public.credential_records', 'SELECT') "
                                + "AND has_table_privilege(current_user, 'public.credential_records', 'INSERT')")) {
                    usable = row.next() && row.getBoolean(1);
                }
            }
            if (!usable) {
                return State.NOT_MIGRATED;
            }
            try (ResultSet row = statement.executeQuery("SELECT EXISTS (SELECT 1 FROM credential_records)")) {
                return row.next() && row.getBoolean(1) ? State.HAS_ACCOUNTS : State.EMPTY;
            }
        }
    }
}
