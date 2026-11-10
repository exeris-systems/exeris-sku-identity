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
 * holds a token that opens nothing. An implementation that writes to a database does so through
 * {@link eu.exeris.sku.identity.IdentityComposition#transactionalExecutor()}, so that its write joins the
 * same transaction; a write through the kernel's executor directly, from inside a request, is refused by
 * the connection already being in a transaction.
 *
 * <p>Implementations are called from request threads and must be thread-safe, and must return promptly.
 */
public interface InvitationDelivery {

    /**
     * Delivers the token of one invitation.
     *
     * @param notice the invitation and its token
     */
    void deliver(InvitationNotice notice);
}
