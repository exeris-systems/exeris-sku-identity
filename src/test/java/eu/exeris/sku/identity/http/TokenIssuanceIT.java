package eu.exeris.sku.identity.http;

import eu.exeris.caps.tokenissuer.api.KeyState;
import eu.exeris.caps.tokenissuer.api.SigningKeyInfo;
import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.sku.identity.support.IdentityHarness;
import eu.exeris.sku.identity.support.IdentityHarness.Account;
import eu.exeris.sku.identity.support.TestConfig;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static eu.exeris.sku.identity.support.IdentityHarness.bearer;
import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Access tokens")
class TokenIssuanceIT {

    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final String ED25519_SPKI_PREFIX = "302a300506032b6570032100";

    private static IdentityHarness service;

    @BeforeAll
    static void start() throws Exception {
        service = IdentityHarness.start();
    }

    @AfterAll
    static void stop() {
        service.close();
    }

    private static JsonNode part(String token, int index) {
        return JSON.readTree(Base64.getUrlDecoder().decode(token.split("\\.")[index]));
    }

    private static PublicKey keyOf(IdentityHarness service, String kid) throws Exception {
        JsonNode keys = JSON.readTree(service.composition.jwksPublisher().getJwksJson()).get("keys");
        for (JsonNode key : keys) {
            if (kid.equals(key.get("kid").stringValue())) {
                assertThat(key.get("kty").stringValue()).isEqualTo("OKP");
                assertThat(key.get("crv").stringValue()).isEqualTo("Ed25519");
                byte[] raw = Base64.getUrlDecoder().decode(key.get("x").stringValue());
                byte[] spki = HexFormat.of().parseHex(ED25519_SPKI_PREFIX + HexFormat.of().formatHex(raw));
                return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(spki));
            }
        }
        throw new AssertionError("kid not published: " + kid);
    }

    private static boolean signatureHolds(IdentityHarness service, String token) throws Exception {
        String[] parts = token.split("\\.");
        Signature signature = Signature.getInstance("Ed25519");
        signature.initVerify(keyOf(service, part(token, 0).get("kid").stringValue()));
        signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        return signature.verify(Base64.getUrlDecoder().decode(parts[2]));
    }

    @Test
    @DisplayName("a token is signed with EdDSA under a published key, and the service accepts it")
    void tokenIsVerifiableAgainstTheServedKeys() throws Exception {
        Account account = service.account();
        String token = service.accessToken(account);

        JsonNode header = part(token, 0);
        JsonNode claims = part(token, 1);

        assertThat(header.get("alg").stringValue()).isEqualTo("EdDSA");
        assertThat(signatureHolds(service, token)).isTrue();
        assertThat(claims.get("iss").stringValue()).isEqualTo(TestConfig.ISSUER);
        assertThat(claims.get("sub").stringValue()).isEqualTo(account.subject().toString());
        assertThat(claims.has("sid")).isTrue();
        assertThat(service.send(HttpMethod.GET, "/api/v1/auth/sessions", bearer(token)).code()).isEqualTo(200);
        assertThat(service.send(HttpMethod.GET, "/.well-known/jwks.json").body()).contains(header.get("kid").stringValue());
    }

    @Test
    @DisplayName("a token that was tampered with is refused")
    void tamperedTokenIsRefused() {
        String token = service.accessToken(service.account());
        String[] parts = token.split("\\.");
        JsonNode claims = part(token, 1);
        String forged = JSON.writeValueAsString(((tools.jackson.databind.node.ObjectNode) claims.deepCopy())
                .put("sub", UUID.randomUUID().toString()));
        String tampered = parts[0] + "." + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(forged.getBytes(StandardCharsets.UTF_8)) + "." + parts[2];

        assertThat(service.send(HttpMethod.GET, "/api/v1/auth/sessions", bearer(tampered)).code()).isEqualTo(401);
    }

    @Test
    @DisplayName("a subject with one membership gets that tenant, its role and the scopes of the role")
    void singleMembershipIsInTheToken() {
        UUID tenant = UUID.randomUUID();
        JsonNode admin = part(service.accessToken(service.member(tenant, "admin")), 1);
        JsonNode member = part(service.accessToken(service.member(tenant, "member")), 1);

        assertThat(admin.get("tid").stringValue()).isEqualTo(tenant.toString());
        assertThat(admin.get("roles").get(0).stringValue()).isEqualTo("admin");
        assertThat(admin.get("scope").stringValue()).isEqualTo("invitations:write");
        assertThat(member.get("tid").stringValue()).isEqualTo(tenant.toString());
        assertThat(member.get("roles").get(0).stringValue()).isEqualTo("member");
        assertThat(member.has("scope")).isFalse();
    }

    @Test
    @DisplayName("a subject with no membership, or with several, gets a token that names no tenant")
    void noActiveTenant() {
        Account none = service.account();
        Account several = service.member(UUID.randomUUID(), "admin");
        service.directory.grant(UUID.randomUUID(), several.subject(), "admin");

        for (Account account : List.of(none, several)) {
            JsonNode claims = part(service.accessToken(account), 1);
            assertThat(claims.has("tid")).isFalse();
            assertThat(claims.has("roles")).isFalse();
            assertThat(claims.has("scope")).isFalse();
        }
    }

    private static Set<String> publishedKids(IdentityHarness service) {
        JsonNode keys = JSON.readTree(service.composition.jwksPublisher().getJwksJson()).get("keys");
        Set<String> kids = new java.util.HashSet<>();
        keys.forEach(key -> kids.add(key.get("kid").stringValue()));
        return kids;
    }

    @Test
    @DisplayName("a new key is published before it signs, and the key it replaces stays published while it retires")
    void rotationKeepsTheOldKey() throws Exception {
        try (IdentityHarness own = IdentityHarness.start()) {
            rotate(own);
        }
    }

    private static void rotate(IdentityHarness own) throws Exception {
        String before = own.accessToken(own.account());
        String oldKid = part(before, 0).get("kid").stringValue();

        SigningKeyInfo pending = own.composition.services().signingKeys().rotateKeys();

        assertThat(pending.state()).isEqualTo(KeyState.PENDING);
        assertThat(publishedKids(own)).contains(oldKid, pending.kid());
        assertThat(part(own.accessToken(own.account()), 0).get("kid").stringValue())
                .as("a pending key does not sign").isEqualTo(oldKid);

        try (var owner = own.database.owner();
             var statement = owner.prepareStatement(
                     "UPDATE exeris_signing_keys SET created_at = created_at - interval '1 hour', expires_at = expires_at - interval '1 hour' WHERE kid = ?")) {
            statement.setString(1, pending.kid());
            statement.executeUpdate();
        }
        SigningKeyInfo promoted = own.composition.services().signingKeys().rotateKeys();

        assertThat(promoted.kid()).isEqualTo(pending.kid());
        assertThat(promoted.state()).isEqualTo(KeyState.ACTIVE);
        assertThat(own.composition.services().signingKeys().listKeyGenerations())
                .anySatisfy(info -> {
                    assertThat(info.kid()).isEqualTo(oldKid);
                    assertThat(info.state()).isEqualTo(KeyState.RETIRING);
                });
        assertThat(publishedKids(own)).contains(oldKid, pending.kid());
        assertThat(signatureHolds(own, before)).isTrue();
        assertThat(own.send(HttpMethod.GET, "/api/v1/auth/sessions", bearer(before)).code()).isEqualTo(200);
        String after = own.accessToken(own.account());
        assertThat(part(after, 0).get("kid").stringValue()).isEqualTo(pending.kid());
        assertThat(signatureHolds(own, after)).isTrue();
    }
}
