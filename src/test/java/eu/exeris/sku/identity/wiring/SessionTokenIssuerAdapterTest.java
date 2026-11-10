package eu.exeris.sku.identity.wiring;

import eu.exeris.caps.tokenissuer.api.AccessTokenIssuer;
import eu.exeris.caps.tokenissuer.api.IssuedAccessToken;
import eu.exeris.caps.tokenissuer.api.TokenIssueRequest;
import eu.exeris.sku.identity.auth.MembershipDirectory;
import eu.exeris.sku.identity.support.InMemoryMembershipDirectory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("SessionTokenIssuerAdapter")
class SessionTokenIssuerAdapterTest {

    private final AtomicReference<TokenIssueRequest> issued = new AtomicReference<>();
    private final MembershipDirectory directory = new InMemoryMembershipDirectory();
    private final UUID subject = UUID.randomUUID();
    private final UUID session = UUID.randomUUID();

    private final AccessTokenIssuer fake = new AccessTokenIssuer() {
        @Override
        public IssuedAccessToken issueAccessToken(UUID subjectId, UUID sessionId) {
            throw new AssertionError("the adapter must use the request form");
        }

        @Override
        public IssuedAccessToken issueAccessToken(TokenIssueRequest request) {
            issued.set(request);
            return new IssuedAccessToken("opaque", Instant.now().plusSeconds(60), "Bearer");
        }
    };

    private final SessionTokenIssuerAdapter adapter = new SessionTokenIssuerAdapter(fake, directory);

    @Test
    @DisplayName("one membership puts its tenant and role in the token, and an administrator gets the invitation scope")
    void singleMembershipNamesTheTenant() {
        UUID tenant = UUID.randomUUID();
        directory.grant(tenant, subject, "admin");

        var token = adapter.issueAccessToken(subject, session);

        assertThat(token.token()).isEqualTo("opaque");
        assertThat(issued.get().subjectId()).isEqualTo(subject);
        assertThat(issued.get().sessionId()).isEqualTo(session);
        assertThat(issued.get().tenantId()).isEqualTo(tenant.toString());
        assertThat(issued.get().roles()).containsExactly("admin");
        assertThat(issued.get().customClaims()).containsEntry("scope", "invitations:write");
    }

    @Test
    @DisplayName("a role that administers nothing carries no scope claim")
    void plainMemberHasNoScope() {
        UUID tenant = UUID.randomUUID();
        directory.grant(tenant, subject, "member");

        adapter.issueAccessToken(subject, session);

        assertThat(issued.get().tenantId()).isEqualTo(tenant.toString());
        assertThat(issued.get().roles()).containsExactly("member");
        assertThat(issued.get().customClaims()).doesNotContainKey("scope");
    }

    @Test
    @DisplayName("no membership and several memberships both give a token with no tenant and no role")
    void ambiguousOrMissingMembershipIsTenantless() {
        adapter.issueAccessToken(subject, session);
        assertThat(issued.get().tenantId()).isNull();
        assertThat(issued.get().roles()).isEmpty();

        directory.grant(UUID.randomUUID(), subject, "owner");
        directory.grant(UUID.randomUUID(), subject, "owner");
        adapter.issueAccessToken(subject, session);

        assertThat(issued.get().tenantId()).isNull();
        assertThat(issued.get().roles()).isEmpty();
        assertThat(issued.get().customClaims()).doesNotContainKey("scope");
    }
}
