package eu.exeris.sku.identity.auth;

/** The scope strings access tokens issued by this service can carry. */
public final class Scopes {

    /** Permits issuing, listing and revoking invitations of the token's tenant. */
    public static final String INVITATIONS_WRITE = "invitations:write";

    private Scopes() {
    }
}
