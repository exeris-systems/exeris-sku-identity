package eu.exeris.sku.identity.persistence;

import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.sku.identity.auth.TenantScope;
import eu.exeris.sku.identity.support.JdbcTransactionalExecutor;
import eu.exeris.sku.identity.support.PostgresSupport;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("JoiningTransactionalExecutor")
class JoiningTransactionalExecutorTest {

    private static PostgresSupport.Database database;
    private static JoiningTransactionalExecutor executor;

    @BeforeAll
    static void start() throws Exception {
        database = PostgresSupport.newDatabase();
        try (Connection owner = database.owner(); Statement statement = owner.createStatement()) {
            statement.execute("CREATE TABLE joined_notes (id UUID PRIMARY KEY, note TEXT NOT NULL)");
            statement.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON joined_notes TO " + PostgresSupport.serviceRole());
        }
        executor = JoiningTransactionalExecutor.wrap(new JdbcTransactionalExecutor(database));
    }

    private static void insert(PersistenceConnection connection, UUID id) {
        var statement = connection.prepare("INSERT INTO joined_notes (id, note) VALUES ($1, 'x')");
        statement.bindUuid(0, id);
        statement.executeUpdate();
    }

    private static long count(UUID id) throws SQLException {
        try (Connection owner = database.owner(); Statement statement = owner.createStatement();
             ResultSet rows = statement.executeQuery("SELECT count(*) FROM joined_notes WHERE id = '" + id + "'")) {
            rows.next();
            return rows.getLong(1);
        }
    }

    @Test
    @DisplayName("calls made inside a unit run on its connection and see its uncommitted writes")
    void nestedCallsJoin() throws Exception {
        UUID id = UUID.randomUUID();
        List<Boolean> seen = new ArrayList<>();

        executor.inTransaction(() -> {
            executor.executeManaged(connection -> insert(connection, id));
            seen.add(executor.query(connection -> {
                var statement = connection.prepare("UPDATE joined_notes SET note = 'y' WHERE id = $1");
                statement.bindUuid(0, id);
                return statement.executeUpdate() == 1;
            }));
            seen.add(JoiningTransactionalExecutor.joined());
            return null;
        });

        assertThat(seen).containsExactly(true, true);
        assertThat(count(id)).isEqualTo(1);
        assertThat(JoiningTransactionalExecutor.joined()).isFalse();
    }

    @Test
    @DisplayName("an exception rolls back every joined write")
    void exceptionRollsBack() throws Exception {
        UUID first = UUID.randomUUID();
        UUID second = UUID.randomUUID();

        assertThatThrownBy(() -> executor.inTransaction(() -> {
            executor.executeManaged(connection -> insert(connection, first));
            executor.executeManaged(connection -> insert(connection, second));
            throw new IllegalStateException("fail");
        })).isInstanceOf(IllegalStateException.class);

        assertThat(count(first)).isZero();
        assertThat(count(second)).isZero();
    }

    @Test
    @DisplayName("an action after commit runs once after the commit and never after a rollback")
    void afterCommit() throws Exception {
        UUID id = UUID.randomUUID();
        List<Long> visible = new ArrayList<>();

        executor.inTransaction(() -> {
            executor.executeManaged(connection -> insert(connection, id));
            JoiningTransactionalExecutor.afterCommit(() -> {
                try {
                    visible.add(count(id));
                } catch (SQLException e) {
                    throw new IllegalStateException(e);
                }
            });
            assertThat(visible).as("not yet").isEmpty();
            return null;
        });
        assertThat(visible).containsExactly(1L);

        List<String> dropped = new ArrayList<>();
        assertThatThrownBy(() -> executor.inTransaction(() -> {
            JoiningTransactionalExecutor.afterCommit(() -> dropped.add("ran"));
            throw new IllegalStateException("fail");
        })).isInstanceOf(IllegalStateException.class);
        assertThat(dropped).isEmpty();

        JoiningTransactionalExecutor.afterCommit(() -> dropped.add("at once"));
        assertThat(dropped).containsExactly("at once");
    }

    @Test
    @DisplayName("execute, which manages its own boundaries, and another isolation level are refused inside a unit")
    void unjoinableCallsAreRefused() {
        executor.inTransaction(() -> {
            assertThatThrownBy(() -> executor.execute(connection -> { }))
                    .isInstanceOf(IllegalStateException.class).hasMessageContaining("cannot join");
            assertThatThrownBy(() -> executor.executeManaged(TransactionIsolation.SERIALIZABLE, false,
                    connection -> { })).isInstanceOf(IllegalStateException.class);
            return null;
        });
    }

    @Test
    @DisplayName("a call under another isolation key than the unit began with is refused")
    void anotherStorageContextIsRefused() {
        UUID tenant = UUID.randomUUID();
        TenantScope.run(tenant, () -> executor.inTransaction(() -> {
            TenantScope.run(UUID.randomUUID(), () -> assertThatThrownBy(
                    () -> executor.executeManaged(connection -> { })).isInstanceOf(IllegalStateException.class));
            executor.executeManaged(connection -> { });
            return null;
        }));
    }

    @Test
    @DisplayName("two wrappers over one delegate are two executors: the second is refused inside the first one's unit")
    void anotherWrapperIsRefused() {
        JdbcTransactionalExecutor delegate = new JdbcTransactionalExecutor(database);
        JoiningTransactionalExecutor first = JoiningTransactionalExecutor.wrap(delegate);
        JoiningTransactionalExecutor second = JoiningTransactionalExecutor.wrap(delegate);

        assertThat(second).isNotSameAs(first);
        first.inTransaction(() -> {
            assertThatThrownBy(() -> second.executeManaged(connection -> { }))
                    .isInstanceOf(IllegalStateException.class).hasMessageContaining("another executor");
            assertThatThrownBy(() -> second.inTransaction(() -> null))
                    .isInstanceOf(IllegalStateException.class).hasMessageContaining("another executor");
            first.executeManaged(connection -> { });
            return null;
        });
    }

    @Test
    @DisplayName("outside a unit every call goes to the delegate, and wrapping twice yields the same executor")
    void transparentOutsideAUnit() throws Exception {
        UUID id = UUID.randomUUID();

        executor.executeManaged(connection -> insert(connection, id));

        assertThat(count(id)).isEqualTo(1);
        assertThat(JoiningTransactionalExecutor.wrap(executor)).isSameAs(executor);
    }
}
