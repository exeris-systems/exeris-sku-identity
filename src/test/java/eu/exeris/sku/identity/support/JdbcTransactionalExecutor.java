package eu.exeris.sku.identity.support;

import eu.exeris.kernel.community.persistence.jdbc.JdbcPersistenceConnection;
import eu.exeris.kernel.spi.context.KernelProviders;
import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.function.Function;

/**
 * A hand-written executor over plain JDBC. Every call opens its own connection as the service role and
 * publishes the isolation key of the bound storage context as {@code exeris.tenant_id} for the
 * transaction, which is what the row-level-security policies read.
 */
public final class JdbcTransactionalExecutor implements TransactionalExecutor {

    private final PostgresSupport.Database database;

    /**
     * @param database the database to connect to as the service role
     */
    public JdbcTransactionalExecutor(PostgresSupport.Database database) {
        this.database = database;
    }

    @Override
    public void execute(TransactionalWork work) {
        executeManaged(work);
    }

    @Override
    public void executeManaged(TransactionalWork work) {
        inTransaction(connection -> {
            work.run(connection);
            return null;
        });
    }

    @Override
    public void executeManaged(TransactionIsolation isolation, boolean readOnly, TransactionalWork work) {
        executeManaged(work);
    }

    @Override
    public <T> T query(Function<PersistenceConnection, T> query) {
        return inTransaction(query);
    }

    private <T> T inTransaction(Function<PersistenceConnection, T> work) {
        try (Connection jdbc = database.service()) {
            PersistenceConnection connection = new JdbcPersistenceConnection(jdbc);
            connection.beginTransaction();
            try {
                try (PreparedStatement key = jdbc.prepareStatement("SELECT set_config('exeris.tenant_id', ?, true)")) {
                    key.setString(1, KernelProviders.STORAGE_CONTEXT.isBound()
                            ? KernelProviders.STORAGE_CONTEXT.get().isolationKey().orElse("")
                            : "");
                    key.execute();
                }
                T result = work.apply(connection);
                connection.commit();
                return result;
            } catch (RuntimeException | SQLException e) {
                connection.rollback();
                throw e instanceof RuntimeException r ? r : new IllegalStateException(e);
            }
        } catch (SQLException e) {
            throw new IllegalStateException(e);
        }
    }
}
