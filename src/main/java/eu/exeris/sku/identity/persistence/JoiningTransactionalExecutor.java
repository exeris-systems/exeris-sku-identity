package eu.exeris.sku.identity.persistence;

import eu.exeris.kernel.spi.context.KernelProviders;
import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.PersistenceStatement;
import eu.exeris.kernel.spi.persistence.QueryResult;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * A {@link TransactionalExecutor} that lets several capabilities write in one transaction.
 *
 * <p>The kernel's executor has no propagation: a call to {@code executeManaged} opens a transaction of its
 * own, and inside a kernel request it reuses the request's connection, which is already in one. This
 * wrapper adds the missing rule. Inside {@link #inTransaction}, every call made through the same wrapper
 * runs on the unit's connection, without a begin or a commit of its own, and sees the unit's earlier
 * writes. Outside a unit, every call goes to the delegate unchanged, so the wrapper is transparent to a
 * capability that is not being joined.
 *
 * <p>A unit is bound to the isolation key that was published when it began; a call under another key is
 * refused, because the connection's tenant is fixed for the transaction. A unit also refuses
 * {@link #execute}, which manages its own boundaries and cannot be joined, and any isolation level other
 * than read committed.
 *
 * <p>The delegate may run a unit again after a serialization failure or a deadlock. Work passed to
 * {@link #inTransaction} must therefore be safe to run more than once, and everything queued with
 * {@link #afterCommit} by an attempt that did not commit is dropped.
 */
public final class JoiningTransactionalExecutor implements TransactionalExecutor {

    private static final System.Logger LOG = System.getLogger(JoiningTransactionalExecutor.class.getName());

    private record Joined(JoiningTransactionalExecutor owner, PersistenceConnection connection, String isolationKey,
                          List<Runnable> afterCommit) {
    }

    private static final ScopedValue<Joined> JOINED = ScopedValue.newInstance();

    private final TransactionalExecutor delegate;

    private JoiningTransactionalExecutor(TransactionalExecutor delegate) {
        this.delegate = delegate;
    }

    /**
     * Wraps an executor. An executor that already joins is returned as it is; wrapping the same
     * delegate twice gives two instances. Only calls through one instance join one another's unit, and a
     * call through a second instance inside a unit is refused. A host that wants to take part in the
     * composition's units uses the composition's own instance, or passes an instance it wrapped to the
     * composition so that both are the same one.
     *
     * @param delegate the executor that opens the transactions
     * @return the joining executor
     */
    public static JoiningTransactionalExecutor wrap(TransactionalExecutor delegate) {
        Objects.requireNonNull(delegate, "delegate must not be null");
        return delegate instanceof JoiningTransactionalExecutor joining ? joining : new JoiningTransactionalExecutor(delegate);
    }

    /**
     * Runs the work in one transaction. Every call the work makes through this executor, directly or
     * through a capability constructed over it, joins that transaction. The transaction commits when the
     * work returns and rolls back when it throws.
     *
     * <p>Called inside a unit of this executor, the work simply runs as part of it.
     *
     * @param work the work; safe to run again
     * @param <T>  the result type
     * @return what the work returned
     */
    public <T> T inTransaction(Supplier<T> work) {
        Objects.requireNonNull(work, "work must not be null");
        Joined current = currentOrNull();
        if (current != null) {
            return work.get();
        }
        List<Runnable> afterCommit = new ArrayList<>();
        Object[] result = new Object[1];
        delegate.executeManaged(connection -> {
            afterCommit.clear();
            Joined unit = new Joined(this, connection, isolationKey(), afterCommit);
            result[0] = ScopedValue.where(JOINED, unit).call(work::get);
        });
        for (Runnable action : afterCommit) {
            try {
                action.run();
            } catch (RuntimeException e) {
                LOG.log(System.Logger.Level.WARNING, "an action after commit failed: {0}", e.getClass().getName());
            }
        }
        @SuppressWarnings("unchecked")
        T typed = (T) result[0];
        return typed;
    }

    /**
     * Queues an action to run once the unit commits. The action is dropped when the unit rolls back, and
     * runs at once when there is no unit.
     *
     * @param action what to run
     */
    public static void afterCommit(Runnable action) {
        Objects.requireNonNull(action, "action must not be null");
        if (JOINED.isBound()) {
            JOINED.get().afterCommit().add(action);
        } else {
            action.run();
        }
    }

    /** Whether the calling thread is inside a unit. */
    public static boolean joined() {
        return JOINED.isBound();
    }

    private Joined currentOrNull() {
        if (!JOINED.isBound()) {
            return null;
        }
        Joined unit = JOINED.get();
        if (unit.owner() != this) {
            throw new IllegalStateException("a transaction of another executor is active");
        }
        if (!unit.isolationKey().equals(isolationKey())) {
            throw new IllegalStateException("the storage context changed inside a transaction");
        }
        return unit;
    }

    private static String isolationKey() {
        return KernelProviders.STORAGE_CONTEXT.isBound()
                ? KernelProviders.STORAGE_CONTEXT.get().isolationKey().orElse("")
                : "";
    }

    @Override
    public void execute(TransactionalWork work) {
        if (currentOrNull() != null) {
            throw new IllegalStateException("execute manages its own transaction boundaries and cannot join one");
        }
        delegate.execute(work);
    }

    @Override
    public void executeManaged(TransactionalWork work) {
        Joined unit = currentOrNull();
        if (unit == null) {
            delegate.executeManaged(work);
        } else {
            work.run(new JoinedConnection(unit.connection()));
        }
    }

    @Override
    public void executeManaged(TransactionIsolation isolation, boolean readOnly, TransactionalWork work) {
        Joined unit = currentOrNull();
        if (unit == null) {
            delegate.executeManaged(isolation, readOnly, work);
            return;
        }
        requireReadCommitted(isolation);
        work.run(new JoinedConnection(unit.connection()));
    }

    @Override
    public <T> T query(Function<PersistenceConnection, T> query) {
        Joined unit = currentOrNull();
        return unit == null ? delegate.query(query) : query.apply(new JoinedConnection(unit.connection()));
    }

    @Override
    public <T> T inReadSession(TransactionIsolation isolation, Function<ReadSession, T> work) {
        Joined unit = currentOrNull();
        if (unit == null) {
            return delegate.inReadSession(isolation, work);
        }
        requireReadCommitted(isolation);
        PersistenceConnection connection = new JoinedConnection(unit.connection());
        return work.apply(new ReadSession() {
            @Override
            public <R> R query(Function<PersistenceConnection, R> query) {
                return query.apply(connection);
            }
        });
    }

    private static void requireReadCommitted(TransactionIsolation isolation) {
        if (isolation != TransactionIsolation.READ_COMMITTED) {
            throw new IllegalStateException("a joined transaction runs at read committed, not " + isolation);
        }
    }

    /** The unit's connection with its transaction control withdrawn: only the unit's owner ends it. */
    private record JoinedConnection(PersistenceConnection connection) implements PersistenceConnection {

        @Override
        public PersistenceStatement prepare(String sql) {
            return connection.prepare(sql);
        }

        @Override
        public QueryResult executeQuery(String sql) {
            return connection.executeQuery(sql);
        }

        @Override
        public long executeUpdate(String sql) {
            return connection.executeUpdate(sql);
        }

        @Override
        public void beginTransaction() {
            throw new IllegalStateException("the transaction is managed by the enclosing unit");
        }

        @Override
        public void beginTransaction(TransactionIsolation isolation, boolean readOnly) {
            throw new IllegalStateException("the transaction is managed by the enclosing unit");
        }

        @Override
        public void commit() {
            throw new IllegalStateException("the transaction is managed by the enclosing unit");
        }

        @Override
        public void rollback() {
            throw new IllegalStateException("the transaction is managed by the enclosing unit");
        }

        @Override
        public boolean inTransaction() {
            return connection.inTransaction();
        }

        @Override
        public <T> Optional<T> unwrap(Class<T> type) {
            return connection.unwrap(type);
        }

        @Override
        public boolean isOpen() {
            return connection.isOpen();
        }

        @Override
        public void close() {
            // the unit's owner closes the connection
        }
    }
}
