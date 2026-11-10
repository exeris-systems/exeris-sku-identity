package eu.exeris.sku.identity.auth;

/**
 * Hands the single-use token of an invitation to the invitee's mailbox. The host that owns the mail
 * channel implements it.
 *
 * <p>The token is the proof that the person accepting controls the mailbox, so it travels to the invitee
 * and to nothing else: the service never returns it to the inviter, never logs it and never stores it in
 * readable form. An implementation keeps to the same rule: it must not log, return or store the token in
 * readable form; handing it to a durable outbox counts as delivered.
 *
 * <p>{@link #deliver} runs inside the transaction that stores the invitation. If it throws, nothing is
 * stored and the inviter is told the delivery failed. If it returns and the commit then fails, the invitee
 * holds a token that opens nothing.
 *
 * <p>The executor may run the transaction again after a serialization failure or a deadlock, so one
 * request can call {@code deliver} more than once, each time with a different token; only the token of the
 * attempt that commits opens anything. The call happens while the transaction holds a database connection,
 * so it must return promptly: it hands the token over and does not wait for a mail server.
 *
 * <p>An implementation that writes to the service's database must write through the executor that joins
 * the transaction, so that its write commits and rolls back with the invitation. A host part named to the
 * launcher receives that executor by implementing {@link JoinsServiceTransactions}; a host that embeds the
 * library reads it from {@link eu.exeris.sku.identity.IdentityComposition#transactionalExecutor()}. A write
 * through any other executor is not part of the transaction: on the connection the request already holds it
 * is refused and rolls the transaction back, and under another storage context it commits on its own and
 * outlives a rollback.
 *
 * <p>Implementations are called from request threads and must be thread-safe.
 */
public interface InvitationDelivery {

    /**
     * Delivers the token of one invitation.
     *
     * @param notice the invitation and its token
     */
    void deliver(InvitationNotice notice);
}
