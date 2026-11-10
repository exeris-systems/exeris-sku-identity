package eu.exeris.sku.identity.auth;

import eu.exeris.kernel.spi.persistence.TransactionalExecutor;

/**
 * Optionally implemented by a host part that writes to the service's database inside the service's own
 * transactions, such as an {@link InvitationDelivery} that records into an outbox table or a
 * {@link MembershipDirectory} that stores grants there.
 *
 * <p>A host part named to the standalone launcher is created through its public no-argument constructor
 * before the kernel boots, so it cannot be given the executor at construction. When it implements this
 * interface, the launcher calls {@link #joinTransactionsOf} once, after the composition is built and
 * before the service accepts any request or runs any job, with the executor whose units the composition
 * opens. A part that is not handed the executor must not write to the service's database from inside a
 * request. A host that embeds the library builds the composition itself and reads the same executor from
 * {@code IdentityComposition.transactionalExecutor()}.
 *
 * <p>The executor is the one to write through. A write through the kernel's own executor, or any other,
 * does not take part in the unit: when it lands on the connection the request already holds it is
 * refused, because that connection is in a transaction, and the refusal rolls the whole unit back; when
 * it runs under another storage context it uses a connection of its own and commits independently of the
 * unit, so it survives a rollback of the invitation or the account.
 *
 * <p>The method is called once, from the thread that starts the service. Calls the part later receives
 * from request threads see the executor it stored, so the part stores it in a way that is safely
 * published, such as a {@code volatile} or a final field of an object created for the purpose.
 */
public interface JoinsServiceTransactions {

    /**
     * Receives the executor that joins the composition's units.
     *
     * @param executor the executor to write through while inside a unit of the service; outside a unit it
     *                 behaves as the kernel's executor does
     */
    void joinTransactionsOf(TransactionalExecutor executor);
}
