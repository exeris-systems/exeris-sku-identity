package eu.exeris.sku.identity.launcher;

import eu.exeris.caps.credentialstore.api.CredentialProvisioning;
import eu.exeris.caps.credentialstore.api.model.PasswordPolicy;
import eu.exeris.caps.credentialstore.api.model.ProvisionResult;
import eu.exeris.kernel.community.security.Argon2idPasswordEncoder;
import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import eu.exeris.sku.identity.IdentityComposition;
import eu.exeris.sku.identity.auth.JoinsServiceTransactions;
import eu.exeris.sku.identity.auth.Membership;
import eu.exeris.sku.identity.auth.MembershipDirectory;
import eu.exeris.sku.identity.config.IdentityConfig;
import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import eu.exeris.sku.identity.support.JdbcTransactionalExecutor;
import eu.exeris.sku.identity.support.PostgresSupport;
import eu.exeris.sku.identity.support.RecordingNotificationDispatcher;
import eu.exeris.sku.identity.support.TestConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The transactional seam of the command, over a real database and the composition's own wiring, with no
 * kernel: the unit either leaves an account (and its grant) or leaves nothing.
 */
@DisplayName("Owner provisioning in one transaction")
class OwnerProvisioningIT {

    private static final String GRANT_TABLE = "host_memberships";

    /** A directory that writes its grants into the service's database through the executor it is joined to. */
    private static final class TableDirectory implements MembershipDirectory, JoinsServiceTransactions {
        private volatile TransactionalExecutor executor;
        private final AtomicBoolean failAfterWrite = new AtomicBoolean();

        @Override
        public void joinTransactionsOf(TransactionalExecutor executor) {
            this.executor = executor;
        }

        @Override
        public List<Membership> memberships(UUID subjectId) {
            return List.of();
        }

        @Override
        public void grant(UUID tenantId, UUID subjectId, String role) {
            executor.executeManaged(connection -> {
                var statement = connection.prepare(
                        "INSERT INTO " + GRANT_TABLE + " (tenant_id, subject_id, role) VALUES ($1::uuid, $2::uuid, $3)");
                statement.bindString(0, tenantId.toString());
                statement.bindString(1, subjectId.toString());
                statement.bindString(2, role);
                statement.executeUpdate();
            });
            if (failAfterWrite.get()) {
                throw new IllegalStateException("the directory failed after writing");
            }
        }
    }

    /** Runs the first unit to its end, then fails as a serialization failure would, and runs it again. */
    private static final class RetryOnceExecutor implements TransactionalExecutor {
        private static final class Retryable extends RuntimeException {
            Retryable() {
                super(null, null, false, false);
            }
        }

        private final TransactionalExecutor delegate;
        private final AtomicBoolean armed = new AtomicBoolean();

        RetryOnceExecutor(TransactionalExecutor delegate) {
            this.delegate = delegate;
        }

        void arm() {
            armed.set(true);
        }

        @Override
        public void execute(TransactionalWork work) {
            delegate.execute(work);
        }

        @Override
        public void executeManaged(TransactionalWork work) {
            if (armed.getAndSet(false)) {
                try {
                    delegate.executeManaged(connection -> {
                        work.run(connection);
                        throw new Retryable();
                    });
                } catch (Retryable expected) {
                    // the attempt rolled back; the delegate runs the unit again
                }
            }
            delegate.executeManaged(work);
        }

        @Override
        public void executeManaged(TransactionIsolation isolation, boolean readOnly, TransactionalWork work) {
            delegate.executeManaged(isolation, readOnly, work);
        }

        @Override
        public <T> T query(Function<PersistenceConnection, T> query) {
            return delegate.query(query);
        }
    }

    /** One call to the credential store's first-account operation. */
    private record Attempt(char[] array, String contentAtCall, UUID subjectId, String loginIdentifier) {
    }

    /** Records every call, then hands it on to the real provisioning or fails as told. */
    private static final class RecordingProvisioning implements CredentialProvisioning {
        private final CredentialProvisioning real;
        private final RuntimeException failure;
        private final List<String> events;
        final List<Attempt> attempts = new CopyOnWriteArrayList<>();

        RecordingProvisioning(CredentialProvisioning real, RuntimeException failure, List<String> events) {
            this.real = real;
            this.failure = failure;
            this.events = events;
        }

        RecordingProvisioning(CredentialProvisioning real, RuntimeException failure) {
            this(real, failure, new CopyOnWriteArrayList<>());
        }

        @Override
        public ProvisionResult provisionVerified(UUID subjectId, String loginIdentifier, char[] password) {
            return real.provisionVerified(subjectId, loginIdentifier, password);
        }

        @Override
        public Optional<ProvisionResult> provisionFirstVerified(UUID subjectId, String loginIdentifier,
                                                                char[] password) {
            events.add("provisionFirstVerified");
            attempts.add(new Attempt(password, new String(password), subjectId, loginIdentifier));
            if (failure != null) {
                throw failure;
            }
            return real.provisionFirstVerified(subjectId, loginIdentifier, password);
        }
    }

    /** Hands every connection of its delegate to the work through a proxy that logs each statement. */
    private static final class StatementLog implements TransactionalExecutor {
        private final TransactionalExecutor delegate;
        private final List<String> events;

        StatementLog(TransactionalExecutor delegate, List<String> events) {
            this.delegate = delegate;
            this.events = events;
        }

        private PersistenceConnection watch(PersistenceConnection connection) {
            return (PersistenceConnection) Proxy.newProxyInstance(PersistenceConnection.class.getClassLoader(),
                    new Class<?>[] {PersistenceConnection.class}, (proxy, method, args) -> {
                        switch (method.getName()) {
                            case "prepare", "executeQuery", "executeUpdate" -> events.add("statement");
                            case "openBulkInserter" -> events.add("statement");
                            default -> {
                            }
                        }
                        try {
                            return method.invoke(connection, args);
                        } catch (InvocationTargetException e) {
                            throw e.getCause();
                        }
                    });
        }

        @Override
        public void execute(TransactionalWork work) {
            delegate.execute(connection -> work.run(watch(connection)));
        }

        @Override
        public void executeManaged(TransactionalWork work) {
            delegate.executeManaged(connection -> work.run(watch(connection)));
        }

        @Override
        public void executeManaged(TransactionIsolation isolation, boolean readOnly, TransactionalWork work) {
            delegate.executeManaged(isolation, readOnly, connection -> work.run(watch(connection)));
        }

        @Override
        public <T> T query(Function<PersistenceConnection, T> query) {
            return delegate.query(connection -> query.apply(watch(connection)));
        }
    }

    private record Fixture(PostgresSupport.Database database, IdentityComposition composition) {
    }

    private static Fixture fixture() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        try (Connection owner = database.owner(); Statement statement = owner.createStatement()) {
            statement.execute("CREATE TABLE " + GRANT_TABLE
                    + " (tenant_id UUID NOT NULL, subject_id UUID NOT NULL, role TEXT NOT NULL)");
            statement.execute("GRANT SELECT, INSERT ON " + GRANT_TABLE + " TO " + PostgresSupport.serviceRole());
        }
        return new Fixture(database, build(database, null));
    }

    private static IdentityComposition build(PostgresSupport.Database database, TransactionalExecutor executor) {
        IdentityConfig config = TestConfig.load();
        return IdentityComposition.builder()
                .config(config)
                .transactionalExecutor(executor != null ? executor : new JdbcTransactionalExecutor(database))
                .passwordEncoder(new Argon2idPasswordEncoder(config.passwordHashing()))
                .notificationDispatcher(new RecordingNotificationDispatcher())
                .membershipDirectory(new InMemoryMembershipDirectory())
                .build();
    }

    private static String email() {
        return BootstrapOwnerSupport.email();
    }

    private static long count(PostgresSupport.Database database, String table) throws SQLException {
        try (Connection owner = database.owner(); Statement statement = owner.createStatement();
             ResultSet rows = statement.executeQuery("SELECT count(*) FROM " + table)) {
            rows.next();
            return rows.getLong(1);
        }
    }

    private static boolean signsIn(IdentityComposition composition, String email, char[] password) {
        return composition.services().credentialStore().authenticate(email, password).isSuccess();
    }

    @Test
    @DisplayName("It creates one verified account, grants owner in the tenant, and the password signs in")
    void createsTheAccountAndTheGrant() throws Exception {
        Fixture f = fixture();
        InMemoryMembershipDirectory directory = new InMemoryMembershipDirectory();
        UUID tenant = UUID.randomUUID();
        UUID subject = UUID.randomUUID();
        String email = email();
        char[] password = TestConfig.randomPassword();

        OwnerProvisioning.Outcome outcome = OwnerProvisioning.provision(f.composition.transactionalExecutor(),
                f.composition.credentialProvisioning(), directory, email, password.clone(), tenant, subject);

        assertThat(outcome).isEqualTo(new OwnerProvisioning.Provisioned(subject, tenant));
        assertThat(BootstrapOwnerSupport.accounts(f.database)).isEqualTo(1);
        BootstrapOwnerSupport.Credential row = BootstrapOwnerSupport.onlyCredential(f.database);
        assertThat(row.subject()).isEqualTo(subject);
        assertThat(row.loginIdentifier()).isEqualToIgnoringCase(email);
        assertThat(row.verified()).isTrue();
        assertThat(row.verifiedAtSet()).isTrue();
        assertThat(directory.grants()).containsExactly(new InMemoryMembershipDirectory.Grant(tenant, subject, "owner"));
        assertThat(signsIn(f.composition, email, password.clone())).isTrue();
    }

    @Test
    @DisplayName("Without a directory it creates the account and grants nothing")
    void withoutDirectory() throws Exception {
        Fixture f = fixture();
        UUID subject = UUID.randomUUID();

        OwnerProvisioning.Outcome outcome = OwnerProvisioning.provision(f.composition.transactionalExecutor(),
                f.composition.credentialProvisioning(), null, email(), TestConfig.randomPassword(), null, subject);

        assertThat(outcome).isEqualTo(new OwnerProvisioning.Provisioned(subject, null));
        assertThat(BootstrapOwnerSupport.accounts(f.database)).isEqualTo(1);
    }

    @Test
    @DisplayName("A second run finds the account and changes nothing")
    void secondRunIsRefused() throws Exception {
        Fixture f = fixture();
        InMemoryMembershipDirectory directory = new InMemoryMembershipDirectory();
        UUID tenant = UUID.randomUUID();
        OwnerProvisioning.provision(f.composition.transactionalExecutor(), f.composition.credentialProvisioning(),
                directory, email(), TestConfig.randomPassword(), tenant, UUID.randomUUID());

        OwnerProvisioning.Outcome second = OwnerProvisioning.provision(f.composition.transactionalExecutor(),
                f.composition.credentialProvisioning(), directory, email(), TestConfig.randomPassword(), tenant,
                UUID.randomUUID());

        assertThat(second).isEqualTo(new OwnerProvisioning.AccountsExist());
        assertThat(BootstrapOwnerSupport.accounts(f.database)).isEqualTo(1);
        assertThat(directory.grants()).hasSize(1);
    }

    @Test
    @DisplayName("An account created any other way also refuses the run, and no grant is made")
    void foreignAccountRefusesTheRun() throws Exception {
        Fixture f = fixture();
        f.composition.credentialProvisioning().provisionVerified(UUID.randomUUID(), email(),
                TestConfig.randomPassword());
        InMemoryMembershipDirectory directory = new InMemoryMembershipDirectory();

        OwnerProvisioning.Outcome outcome = OwnerProvisioning.provision(f.composition.transactionalExecutor(),
                f.composition.credentialProvisioning(), directory, email(), TestConfig.randomPassword(),
                UUID.randomUUID(), UUID.randomUUID());

        assertThat(outcome).isEqualTo(new OwnerProvisioning.AccountsExist());
        assertThat(BootstrapOwnerSupport.accounts(f.database)).isEqualTo(1);
        assertThat(directory.grants()).isEmpty();
    }

    @Test
    @DisplayName("A grant written through the joined executor commits together with the account")
    void grantCommitsWithTheAccount() throws Exception {
        Fixture f = fixture();
        TableDirectory directory = new TableDirectory();
        directory.joinTransactionsOf(f.composition.transactionalExecutor());

        OwnerProvisioning.provision(f.composition.transactionalExecutor(), f.composition.credentialProvisioning(),
                directory, email(), TestConfig.randomPassword(), UUID.randomUUID(), UUID.randomUUID());

        assertThat(count(f.database, "credential_records")).isEqualTo(1);
        assertThat(count(f.database, GRANT_TABLE)).isEqualTo(1);
    }

    @Test
    @DisplayName("A grant that throws leaves no account and no grant, and a later run with a working directory succeeds")
    void failingGrantLeavesNothing() throws Exception {
        Fixture f = fixture();
        TableDirectory failing = new TableDirectory();
        failing.joinTransactionsOf(f.composition.transactionalExecutor());
        failing.failAfterWrite.set(true);
        InMemoryMembershipDirectory refusing = new InMemoryMembershipDirectory();
        refusing.failNextGrant();
        UUID tenant = UUID.randomUUID();
        char[] password = TestConfig.randomPassword();

        for (MembershipDirectory directory : List.of(failing, refusing)) {
            assertThatThrownBy(() -> OwnerProvisioning.provision(f.composition.transactionalExecutor(),
                    f.composition.credentialProvisioning(), directory, email(), password.clone(), tenant,
                    UUID.randomUUID())).isInstanceOf(RuntimeException.class);

            assertThat(count(f.database, "credential_records")).as("accounts").isZero();
            assertThat(count(f.database, GRANT_TABLE)).as("grants written by the directory").isZero();
        }

        TableDirectory working = new TableDirectory();
        working.joinTransactionsOf(f.composition.transactionalExecutor());
        OwnerProvisioning.Outcome outcome = OwnerProvisioning.provision(f.composition.transactionalExecutor(),
                f.composition.credentialProvisioning(), working, email(), password.clone(), tenant, UUID.randomUUID());

        assertThat(outcome).isInstanceOf(OwnerProvisioning.Provisioned.class);
        assertThat(count(f.database, "credential_records")).isEqualTo(1);
        assertThat(count(f.database, GRANT_TABLE)).isEqualTo(1);
    }

    @Test
    @DisplayName("An address the credential store rejects rolls the unit back and carries no message")
    void invalidAddress() throws Exception {
        Fixture f = fixture();
        InMemoryMembershipDirectory directory = new InMemoryMembershipDirectory();
        String bad = "not-an-address-" + UUID.randomUUID();

        assertThatThrownBy(() -> OwnerProvisioning.provision(f.composition.transactionalExecutor(),
                f.composition.credentialProvisioning(), directory, bad, TestConfig.randomPassword(),
                UUID.randomUUID(), UUID.randomUUID()))
                .isInstanceOf(OwnerProvisioning.InvalidLoginIdentifier.class)
                .hasMessage(null)
                .hasNoCause()
                .satisfies(failure -> assertThat(failure.toString()).doesNotContain(bad));

        assertThat(BootstrapOwnerSupport.accounts(f.database)).isZero();
        assertThat(directory.grants()).isEmpty();
    }

    @Test
    @DisplayName("A unit run again after a failed attempt gives each attempt its own copy and the same subject, and the account signs in")
    void retriedUnitKeepsThePassword() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        RetryOnceExecutor retry = new RetryOnceExecutor(new JdbcTransactionalExecutor(database));
        IdentityComposition composition = build(database, retry);
        RecordingProvisioning spy = new RecordingProvisioning(composition.credentialProvisioning(), null);
        InMemoryMembershipDirectory directory = new InMemoryMembershipDirectory();
        String email = email();
        char[] password = TestConfig.randomPassword();
        String expected = new String(password);
        UUID subject = UUID.randomUUID();
        UUID tenant = UUID.randomUUID();
        retry.arm();

        OwnerProvisioning.Outcome outcome = OwnerProvisioning.provision(composition.transactionalExecutor(), spy,
                directory, email, password, tenant, subject);

        assertThat(outcome).isEqualTo(new OwnerProvisioning.Provisioned(subject, tenant));
        assertThat(spy.attempts).as("the unit ran twice").hasSize(2);
        Attempt first = spy.attempts.get(0);
        Attempt second = spy.attempts.get(1);
        assertThat(first.array()).isNotSameAs(second.array()).isNotSameAs(password);
        assertThat(second.array()).isNotSameAs(password);
        assertThat(first.contentAtCall()).isEqualTo(expected);
        assertThat(second.contentAtCall()).isEqualTo(expected);
        assertThat(first.subjectId()).isEqualTo(subject);
        assertThat(second.subjectId()).isEqualTo(subject);
        assertThat(BootstrapOwnerSupport.accounts(database)).isEqualTo(1);
        assertThat(BootstrapOwnerSupport.onlyCredential(database).subject()).isEqualTo(subject);
        assertThat(directory.grants()).as("the grant is idempotent across attempts")
                .containsOnly(new InMemoryMembershipDirectory.Grant(tenant, subject, "owner"));
        assertThat(signsIn(composition, email, expected.toCharArray())).isTrue();
        assertThat(signsIn(composition, email, new char[password.length])).isFalse();
    }

    @Test
    @DisplayName("Every array handed to the credential store is a copy of the caller's and is zero afterwards, on success and on failure")
    void attemptsAreZeroed() throws Exception {
        Fixture f = fixture();
        char[] password = TestConfig.randomPassword();
        String expected = new String(password);

        RecordingProvisioning ok = new RecordingProvisioning(f.composition.credentialProvisioning(), null);
        OwnerProvisioning.provision(f.composition.transactionalExecutor(), ok, null, email(), password, null,
                UUID.randomUUID());

        for (RuntimeException failure : List.of(new IllegalArgumentException("x"), new IllegalStateException("y"))) {
            RecordingProvisioning failing = new RecordingProvisioning(null, failure);
            PostgresSupport.Database empty = PostgresSupport.newDatabase();
            IdentityComposition other = build(empty, null);
            assertThatThrownBy(() -> OwnerProvisioning.provision(other.transactionalExecutor(), failing, null,
                    email(), password, null, UUID.randomUUID())).isInstanceOf(RuntimeException.class);

            assertThat(failing.attempts).hasSize(1);
            assertThat(failing.attempts.get(0).array()).isNotSameAs(password);
            assertThat(failing.attempts.get(0).contentAtCall()).isEqualTo(expected);
            assertThat(isZero(failing.attempts.get(0).array())).as(failure.getClass().getSimpleName()).isTrue();
        }
        assertThat(ok.attempts).hasSize(1);
        assertThat(ok.attempts.get(0).array()).isNotSameAs(password);
        assertThat(ok.attempts.get(0).contentAtCall()).isEqualTo(expected);
        assertThat(isZero(ok.attempts.get(0).array())).isTrue();
    }

    @Test
    @DisplayName("Nothing precedes the credential store's call inside the unit, and the grant comes after its statements")
    void provisioningIsTheFirstStatement() throws Exception {
        PostgresSupport.Database database = PostgresSupport.newDatabase();
        List<String> events = new CopyOnWriteArrayList<>();
        IdentityComposition composition = build(database, new StatementLog(new JdbcTransactionalExecutor(database), events));
        RecordingProvisioning spy = new RecordingProvisioning(composition.credentialProvisioning(), null, events);
        MembershipDirectory directory = new MembershipDirectory() {
            @Override
            public List<Membership> memberships(UUID subjectId) {
                return List.of();
            }

            @Override
            public void grant(UUID tenantId, UUID subjectId, String role) {
                events.add("grant");
            }
        };

        OwnerProvisioning.Outcome outcome = OwnerProvisioning.provision(composition.transactionalExecutor(), spy,
                directory, email(), TestConfig.randomPassword(), UUID.randomUUID(), UUID.randomUUID());

        assertThat(outcome).isInstanceOf(OwnerProvisioning.Provisioned.class);
        assertThat(events).first().isEqualTo("provisionFirstVerified");
        assertThat(events).as("the store ran statements of its own").contains("statement");
        assertThat(events).last().isEqualTo("grant");
        assertThat(events.stream().filter("provisionFirstVerified"::equals)).hasSize(1);

        events.clear();
        OwnerProvisioning.Outcome refused = OwnerProvisioning.provision(composition.transactionalExecutor(), spy,
                directory, email(), TestConfig.randomPassword(), UUID.randomUUID(), UUID.randomUUID());

        assertThat(refused).isEqualTo(new OwnerProvisioning.AccountsExist());
        assertThat(events).first().isEqualTo("provisionFirstVerified");
        assertThat(events).as("an existing account ends the unit without a grant").doesNotContain("grant");
    }

    @Test
    @DisplayName("A database nobody migrated fails with SQLSTATE 42P01 and creates nothing")
    void unmigrated() throws Exception {
        PostgresSupport.Database database = PostgresSupport.emptyDatabase();
        IdentityComposition composition = build(database, null);
        InMemoryMembershipDirectory directory = new InMemoryMembershipDirectory();

        assertThatThrownBy(() -> OwnerProvisioning.provision(composition.transactionalExecutor(),
                composition.credentialProvisioning(), directory, email(), TestConfig.randomPassword(),
                UUID.randomUUID(), UUID.randomUUID()))
                .satisfies(failure -> assertThat(BootstrapOwnerSupport.sqlStates(failure)).contains("42P01"));

        assertThat(BootstrapOwnerSupport.tables(database)).isEmpty();
        assertThat(directory.grants()).isEmpty();
    }

    @Test
    @DisplayName("A service role that may not read, or may not insert into, the credential table fails with a schema SQLSTATE and creates nothing")
    void missingPrivilege() throws Exception {
        for (String privilege : new String[] {"SELECT", "INSERT"}) {
            Fixture f = fixture();
            BootstrapOwnerSupport.revoke(f.database, privilege);
            InMemoryMembershipDirectory directory = new InMemoryMembershipDirectory();

            assertThatThrownBy(() -> OwnerProvisioning.provision(f.composition.transactionalExecutor(),
                    f.composition.credentialProvisioning(), directory, email(), TestConfig.randomPassword(),
                    UUID.randomUUID(), UUID.randomUUID()))
                    .as(privilege)
                    .satisfies(failure -> assertThat(BootstrapOwnerSupport.sqlStates(failure))
                            .containsAnyOf("42501", "42P01"));

            assertThat(BootstrapOwnerSupport.accounts(f.database)).as(privilege).isZero();
            assertThat(directory.grants()).isEmpty();
        }
    }

    @Test
    @DisplayName("A credential table under row-level security is refused without a message, and nothing is written")
    void rowLevelSecurity() throws Exception {
        Fixture f = fixture();
        BootstrapOwnerSupport.enableRowLevelSecurity(f.database);
        InMemoryMembershipDirectory directory = new InMemoryMembershipDirectory();

        assertThatThrownBy(() -> OwnerProvisioning.provision(f.composition.transactionalExecutor(),
                f.composition.credentialProvisioning(), directory, email(), TestConfig.randomPassword(),
                UUID.randomUUID(), UUID.randomUUID()))
                .isInstanceOf(OwnerProvisioning.CredentialTableUnderRowLevelSecurity.class)
                .hasMessage(null);

        assertThat(BootstrapOwnerSupport.accounts(f.database)).isZero();
        assertThat(directory.grants()).isEmpty();
    }

    private static boolean isZero(char[] array) {
        for (char c : array) {
            if (c != '\0') {
                return false;
            }
        }
        return true;
    }

    @Test
    @DisplayName("The password read from a file with CRLF is exactly the file's content minus the line break")
    void passwordFromFileSignsIn(@TempDir Path dir) throws Exception {
        Fixture f = fixture();
        String password = "in ner  " + new String(TestConfig.randomPassword());
        String email = email();
        char[] read = PasswordFile.read(BootstrapOwnerSupport.passwordFile(dir, password + "\r\n"),
                PasswordPolicy.defaults(), new LauncherEnvironment(java.util.Map.of()));

        OwnerProvisioning.provision(f.composition.transactionalExecutor(), f.composition.credentialProvisioning(),
                null, email, read, null, UUID.randomUUID());

        assertThat(signsIn(f.composition, email, password.toCharArray())).isTrue();
        assertThat(signsIn(f.composition, email, (password + "\r\n").toCharArray())).isFalse();
    }

    @Test
    @DisplayName("Two runs at once against an empty database: one creates the account, the other finds it")
    void concurrentRuns() throws Exception {
        Fixture f = fixture();
        CountDownLatch insideUnit = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        InMemoryMembershipDirectory recorded = new InMemoryMembershipDirectory();
        MembershipDirectory blocking = new MembershipDirectory() {
            @Override
            public List<Membership> memberships(UUID subjectId) {
                return recorded.memberships(subjectId);
            }

            @Override
            public void grant(UUID tenantId, UUID subjectId, String role) {
                insideUnit.countDown();
                try {
                    if (!release.await(60, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("never released");
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(e);
                }
                recorded.grant(tenantId, subjectId, role);
            }
        };
        InMemoryMembershipDirectory other = new InMemoryMembershipDirectory();
        UUID tenant = UUID.randomUUID();
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<OwnerProvisioning.Outcome> first = pool.submit(() -> OwnerProvisioning.provision(
                    f.composition.transactionalExecutor(), f.composition.credentialProvisioning(), blocking, email(),
                    TestConfig.randomPassword(), tenant, UUID.randomUUID()));
            assertThat(insideUnit.await(60, TimeUnit.SECONDS)).as("first run is inside its unit").isTrue();
            Future<OwnerProvisioning.Outcome> second = pool.submit(() -> OwnerProvisioning.provision(
                    f.composition.transactionalExecutor(), f.composition.credentialProvisioning(), other, email(),
                    TestConfig.randomPassword(), tenant, UUID.randomUUID()));

            BootstrapOwnerSupport.awaitCredentialTableWaiter(f.database);
            assertThat(second.isDone()).as("the second run waits for the first").isFalse();
            release.countDown();

            assertThat(first.get(60, TimeUnit.SECONDS)).isInstanceOf(OwnerProvisioning.Provisioned.class);
            assertThat(second.get(60, TimeUnit.SECONDS)).isEqualTo(new OwnerProvisioning.AccountsExist());
        } finally {
            release.countDown();
            pool.shutdownNow();
        }

        assertThat(BootstrapOwnerSupport.accounts(f.database)).isEqualTo(1);
        assertThat(recorded.grants()).hasSize(1);
        assertThat(other.grants()).isEmpty();
    }

    @Test
    @DisplayName("Several runs released together on fresh databases always leave exactly one account and one grant")
    void runsReleasedTogether() throws Exception {
        int rounds = 10;
        int runs = 4;
        for (int round = 0; round < rounds; round++) {
            Fixture f = fixture();
            InMemoryMembershipDirectory directory = new InMemoryMembershipDirectory();
            UUID tenant = UUID.randomUUID();
            CountDownLatch ready = new CountDownLatch(runs);
            CountDownLatch go = new CountDownLatch(1);
            ExecutorService pool = Executors.newFixedThreadPool(runs);
            try {
                List<Future<OwnerProvisioning.Outcome>> outcomes = new ArrayList<>();
                for (int i = 0; i < runs; i++) {
                    outcomes.add(pool.submit(() -> {
                        char[] password = TestConfig.randomPassword();
                        String address = email();
                        ready.countDown();
                        go.await();
                        return OwnerProvisioning.provision(f.composition.transactionalExecutor(),
                                f.composition.credentialProvisioning(), directory, address, password, tenant,
                                UUID.randomUUID());
                    }));
                }
                assertThat(ready.await(60, TimeUnit.SECONDS)).isTrue();
                go.countDown();
                long created = 0;
                long refused = 0;
                for (Future<OwnerProvisioning.Outcome> outcome : outcomes) {
                    OwnerProvisioning.Outcome result = outcome.get(120, TimeUnit.SECONDS);
                    if (result instanceof OwnerProvisioning.Provisioned) {
                        created++;
                    } else if (result instanceof OwnerProvisioning.AccountsExist) {
                        refused++;
                    }
                }
                assertThat(created).as("round " + round).isEqualTo(1);
                assertThat(refused).as("round " + round).isEqualTo(runs - 1);
            } finally {
                pool.shutdownNow();
            }
            assertThat(BootstrapOwnerSupport.accounts(f.database)).as("round " + round).isEqualTo(1);
            assertThat(directory.grants()).as("round " + round).hasSize(1);
        }
    }
}
