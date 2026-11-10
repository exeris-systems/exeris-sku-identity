package eu.exeris.sku.identity.wiring;

import eu.exeris.caps.credentialstore.spi.SessionStore;

import java.util.Objects;
import java.util.UUID;

/** Lets the credential store end every session of a subject whose password changed or was reset. */
public final class SessionRevocationAdapter implements SessionStore {

    private final eu.exeris.caps.sessionmanagement.api.SessionStore sessions;

    /**
     * @param sessions the session store that holds the sessions
     */
    public SessionRevocationAdapter(eu.exeris.caps.sessionmanagement.api.SessionStore sessions) {
        this.sessions = Objects.requireNonNull(sessions, "sessions must not be null");
    }

    @Override
    public void revokeAllForSubject(UUID subjectId) {
        sessions.revokeAllForSubject(subjectId);
    }
}
