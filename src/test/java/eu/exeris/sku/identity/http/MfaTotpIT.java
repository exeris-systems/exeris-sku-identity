package eu.exeris.sku.identity.http;

import eu.exeris.kernel.spi.http.HttpMethod;
import eu.exeris.sku.identity.support.IdentityHarness;
import eu.exeris.sku.identity.support.IdentityHarness.Account;
import eu.exeris.sku.identity.support.TestConfig;
import eu.exeris.sku.identity.support.TestExchange;
import eu.exeris.sku.identity.support.Totp;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

import static eu.exeris.sku.identity.support.IdentityHarness.bearer;
import static eu.exeris.sku.identity.support.IdentityHarness.json;
import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Second factor")
class MfaTotpIT {

    private static final String BASE = "/api/v1/auth";

    private static IdentityHarness service;

    @BeforeAll
    static void start() throws Exception {
        service = IdentityHarness.start();
    }

    @AfterAll
    static void stop() {
        service.close();
    }

    /** Enrols a second factor for a fresh account and returns the account with its secret. */
    private record Enrolled(Account account, String secret, String accessToken) {
    }

    private static Enrolled enrol() {
        Account account = service.account();
        String token = service.accessToken(account);
        TestExchange begin = service.post(BASE + "/mfa/totp/enrollment", Map.of(), bearer(token));
        assertThat(begin.code()).isEqualTo(200);
        String secret = json(begin).get("secret").stringValue();
        assertThat(json(begin).get("provisioningUri").stringValue()).startsWith("otpauth://totp/");
        TestExchange confirm = service.post(BASE + "/mfa/totp/enrollment/confirm",
                Map.of("code", Totp.code(secret, Instant.now())), bearer(token));
        assertThat(confirm.code()).isEqualTo(200);
        return new Enrolled(account, secret, token);
    }

    private static String challenge(Account account) {
        TestExchange login = service.post(BASE + "/login", IdentityHarness.credentials(account));
        assertThat(login.code()).isEqualTo(200);
        JsonNode body = json(login);
        assertThat(body.get("mfaRequired").booleanValue()).isTrue();
        assertThat(body.has("accessToken")).isFalse();
        assertThat(body.has("refreshToken")).isFalse();
        return body.get("challengeToken").stringValue();
    }

    private static String nextCode(String secret) {
        return Totp.codeForStep(secret, Instant.now().getEpochSecond() / 30 + 1);
    }

    private static Map<String, Object> verify(String challenge, String field, String code) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("challengeToken", challenge);
        body.put(field, code);
        return body;
    }

    @Test
    @DisplayName("enrolment needs a correct code, and an active factor cannot be enrolled again")
    void enrolment() {
        Account account = service.account();
        String token = service.accessToken(account);
        String secret = json(service.post(BASE + "/mfa/totp/enrollment", Map.of(), bearer(token)))
                .get("secret").stringValue();

        TestExchange wrong = service.post(BASE + "/mfa/totp/enrollment/confirm",
                Map.of("code", "000000".equals(Totp.code(secret, Instant.now())) ? "111111" : "000000"),
                bearer(token));
        TestExchange right = service.post(BASE + "/mfa/totp/enrollment/confirm",
                Map.of("code", Totp.code(secret, Instant.now())), bearer(token));
        TestExchange again = service.post(BASE + "/mfa/totp/enrollment", Map.of(), bearer(token));

        assertThat(wrong.code()).isEqualTo(400);
        assertThat(wrong.body()).isEqualTo("{\"error\":\"invalid_code\"}");
        assertThat(right.code()).isEqualTo(200);
        assertThat(again.code()).isEqualTo(409);
        assertThat(again.body()).isEqualTo("{\"error\":\"factor_already_enrolled\"}");
    }

    @Test
    @DisplayName("once enrolled, a correct password leads to a challenge, and a correct code to the tokens")
    void challengeAtLogin() {
        Enrolled enrolled = enrol();
        String challenge = challenge(enrolled.account());

        TestExchange verified = service.post(BASE + "/mfa/verify", verify(challenge, "code", nextCode(enrolled.secret())));

        assertThat(verified.code()).isEqualTo(200);
        String access = json(verified).get("accessToken").stringValue();
        assertThat(service.send(HttpMethod.GET, BASE + "/sessions", bearer(access)).code())
                .isEqualTo(200);
        assertThat(service.post(BASE + "/mfa/verify", verify(challenge, "code", nextCode(enrolled.secret()))).code())
                .as("a challenge is used once").isEqualTo(401);
    }

    @Test
    @DisplayName("a code that was accepted cannot be used again")
    void codeReplay() {
        Enrolled enrolled = enrol();
        String code = nextCode(enrolled.secret());
        assertThat(service.post(BASE + "/mfa/verify", verify(challenge(enrolled.account()), "code", code)).code())
                .isEqualTo(200);

        TestExchange replay = service.post(BASE + "/mfa/verify", verify(challenge(enrolled.account()), "code", code));

        assertThat(replay.code()).isEqualTo(401);
        assertThat(replay.body()).isEqualTo("{\"error\":\"invalid_mfa_code\"}");
    }

    @Test
    @DisplayName("a wrong code is refused, and enough wrong codes lock the challenge even for the right code")
    void challengeLocksAfterWrongCodes() {
        Enrolled enrolled = enrol();
        String challenge = challenge(enrolled.account());
        String right = nextCode(enrolled.secret());
        String wrong = "000000".equals(right) ? "111111" : "000000";

        int status = 0;
        for (int i = 0; i < 20 && status != 429; i++) {
            status = service.post(BASE + "/mfa/verify", verify(challenge, "code", wrong)).code();
            assertThat(status).isIn(401, 429);
        }
        TestExchange afterLock = service.post(BASE + "/mfa/verify", verify(challenge, "code", right));

        assertThat(status).isEqualTo(429);
        assertThat(afterLock.code()).isEqualTo(429);
        assertThat(afterLock.body()).isEqualTo("{\"error\":\"challenge_locked\"}");
    }

    @Test
    @DisplayName("a code of another account does not complete this account's challenge")
    void codeOfAnotherAccount() {
        Enrolled owner = enrol();
        Enrolled other = enrol();
        String challenge = challenge(owner.account());

        TestExchange exchange = service.post(BASE + "/mfa/verify", verify(challenge, "code", nextCode(other.secret())));

        assertThat(exchange.code()).isEqualTo(401);
        assertThat(exchange.body()).isEqualTo("{\"error\":\"invalid_mfa_code\"}");
    }

    @Test
    @DisplayName("a recovery code completes a challenge once")
    void recoveryCode() {
        Enrolled enrolled = enrol();
        TestExchange regenerated = service.post(BASE + "/mfa/recovery-codes", Map.of(), bearer(enrolled.accessToken()));
        // The route takes no body; sending one is refused, so ask again without it.
        assertThat(regenerated.code()).isEqualTo(400);
        TestExchange codes = service.send(HttpMethod.POST, BASE + "/mfa/recovery-codes",
                bearer(enrolled.accessToken()));
        assertThat(codes.code()).isEqualTo(200);
        String code = json(codes).get("codes").get(0).stringValue();
        assertThat(json(codes).get("codes").size()).isEqualTo(10);

        TestExchange first = service.post(BASE + "/mfa/verify",
                verify(challenge(enrolled.account()), "recoveryCode", code));
        TestExchange second = service.post(BASE + "/mfa/verify",
                verify(challenge(enrolled.account()), "recoveryCode", code));

        assertThat(first.code()).isEqualTo(200);
        assertThat(second.code()).isEqualTo(401);
        assertThat(second.body()).isEqualTo("{\"error\":\"invalid_mfa_code\"}");
    }

    @Test
    @DisplayName("regenerating recovery codes replaces the caller's codes and leaves another subject's valid")
    void regenerationLeavesOtherSubjectsCodes() {
        Enrolled alice = enrol();
        Enrolled bob = enrol();
        String aliceCode = recoveryCodes(alice).get(0);
        String bobOld = recoveryCodes(bob).get(0);
        String bobNew = recoveryCodes(bob).get(0);

        TestExchange bobsOldCode = service.post(BASE + "/mfa/verify",
                verify(challenge(bob.account()), "recoveryCode", bobOld));
        TestExchange alices = service.post(BASE + "/mfa/verify",
                verify(challenge(alice.account()), "recoveryCode", aliceCode));
        TestExchange bobsNewCode = service.post(BASE + "/mfa/verify",
                verify(challenge(bob.account()), "recoveryCode", bobNew));

        assertThat(bobsOldCode.code()).as("the regenerated-away code").isEqualTo(401);
        assertThat(alices.code()).as("another subject's regeneration does not touch these").isEqualTo(200);
        assertThat(bobsNewCode.code()).isEqualTo(200);
    }

    private static java.util.List<String> recoveryCodes(Enrolled enrolled) {
        TestExchange codes = service.send(HttpMethod.POST, BASE + "/mfa/recovery-codes",
                bearer(enrolled.accessToken()));
        assertThat(codes.code()).isEqualTo(200);
        java.util.List<String> result = new java.util.ArrayList<>();
        json(codes).get("codes").forEach(code -> result.add(code.stringValue()));
        return result;
    }

    @Test
    @DisplayName("enrolment belongs to the caller: another subject cannot confirm it, and beginning one does not replace it")
    void enrolmentIsOwn() {
        Account alice = service.account();
        Account bob = service.account();
        String aliceToken = service.accessToken(alice);
        String bobToken = service.accessToken(bob);
        String aliceSecret = json(service.post(BASE + "/mfa/totp/enrollment", Map.of(), bearer(aliceToken)))
                .get("secret").stringValue();

        TestExchange bobConfirms = service.post(BASE + "/mfa/totp/enrollment/confirm",
                Map.of("code", Totp.code(aliceSecret, Instant.now())), bearer(bobToken));

        assertThat(bobConfirms.code()).as(bobConfirms.body()).isEqualTo(409);
        assertThat(bobConfirms.body()).isEqualTo("{\"error\":\"factor_not_enrolled\"}");
        assertThat(service.post(BASE + "/login", IdentityHarness.credentials(alice)).code()).isEqualTo(200);
        assertThat(json(service.post(BASE + "/login", IdentityHarness.credentials(alice)))
                .has("mfaRequired")).as("alice's factor is not active").isFalse();

        TestExchange bobBegins = service.post(BASE + "/mfa/totp/enrollment", Map.of(), bearer(bobToken));
        assertThat(bobBegins.code()).isEqualTo(200);
        TestExchange aliceConfirms = service.post(BASE + "/mfa/totp/enrollment/confirm",
                Map.of("code", Totp.code(aliceSecret, Instant.now())), bearer(aliceToken));

        assertThat(aliceConfirms.code()).as("bob's begin did not replace alice's secret").isEqualTo(200);
    }

    @Test
    @DisplayName("recovery codes need an active factor")
    void recoveryCodesNeedAFactor() {
        String token = service.accessToken(service.account());

        TestExchange exchange = service.send(HttpMethod.POST, BASE + "/mfa/recovery-codes",
                bearer(token));

        assertThat(exchange.code()).isEqualTo(409);
        assertThat(exchange.body()).isEqualTo("{\"error\":\"factor_not_enrolled\"}");
    }

    @Test
    @DisplayName("exactly one of a code and a recovery code is required")
    void exactlyOneKindOfCode() {
        Enrolled enrolled = enrol();
        String challenge = challenge(enrolled.account());
        Map<String, Object> both = verify(challenge, "code", nextCode(enrolled.secret()));
        both.put("recoveryCode", new String(TestConfig.randomPassword()));

        assertThat(service.post(BASE + "/mfa/verify", both).code()).isEqualTo(400);
        assertThat(service.post(BASE + "/mfa/verify", Map.of("challengeToken", challenge)).code()).isEqualTo(400);
    }

    @Test
    @DisplayName("an unknown challenge is refused")
    void unknownChallenge() {
        TestExchange exchange = service.post(BASE + "/mfa/verify",
                verify("unknown-" + TestConfig.randomBase64(24), "code", "123456"));

        assertThat(exchange.code()).isEqualTo(401);
        assertThat(exchange.body()).isEqualTo("{\"error\":\"invalid_challenge\"}");
    }
}
