package eu.exeris.sku.identity.http;

import eu.exeris.sku.identity.auth.InvitationNotice;
import eu.exeris.sku.identity.support.IdentityHarness;
import eu.exeris.sku.identity.support.TestConfig;
import eu.exeris.sku.identity.support.TestExchange;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static eu.exeris.sku.identity.support.IdentityHarness.bearer;
import static eu.exeris.sku.identity.support.IdentityHarness.json;
import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("An invitation token reaches the invitee and nothing else")
class InvitationTokenSecrecyIT {

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

    /** Collects every JUL record, whatever its level, and everything written to the standard streams. */
    private static final class Capture extends Handler implements AutoCloseable {

        private final List<String> lines = new ArrayList<>();
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();
        private final ByteArrayOutputStream err = new ByteArrayOutputStream();
        private final PrintStream savedOut = System.out;
        private final PrintStream savedErr = System.err;
        private final Logger root = Logger.getLogger("");
        private final Level savedLevel = root.getLevel();

        Capture() {
            root.setLevel(Level.ALL);
            root.addHandler(this);
            setLevel(Level.ALL);
            System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
            System.setErr(new PrintStream(err, true, StandardCharsets.UTF_8));
        }

        @Override
        public synchronized void publish(LogRecord record) {
            // The PostgreSQL driver traces every bound parameter at its finest level, and the capture runs at
            // that level; what is asserted is the service's own output, not the driver's wire trace.
            if (record.getLoggerName() != null && record.getLoggerName().startsWith("org.postgresql")) {
                return;
            }
            StringBuilder line = new StringBuilder(String.valueOf(record.getMessage()));
            if (record.getParameters() != null) {
                for (Object parameter : record.getParameters()) {
                    line.append(' ').append(parameter);
                }
            }
            if (record.getThrown() != null) {
                line.append(' ').append(record.getThrown());
            }
            lines.add(line.toString());
        }

        @Override
        public void flush() {
        }

        synchronized String text() {
            return String.join("\n", lines) + "\n" + out.toString(StandardCharsets.UTF_8) + "\n"
                    + err.toString(StandardCharsets.UTF_8);
        }

        @Override
        public void close() {
            System.setOut(savedOut);
            System.setErr(savedErr);
            root.removeHandler(this);
            root.setLevel(savedLevel);
        }
    }

    private static List<String> forms(String token) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
        String hex = HexFormat.of().formatHex(digest);
        List<String> forms = new ArrayList<>(List.of(token, hex, hex.toUpperCase(),
                Base64.getUrlEncoder().withoutPadding().encodeToString(digest)));
        if (token.startsWith("inv_")) {
            forms.add(token.substring("inv_".length()));
        }
        return forms;
    }

    @Test
    @DisplayName("no response, header, log line or console output carries the token or a hash of it")
    void tokenAppearsOnlyInTheDelivery() throws Exception {
        UUID tenant = UUID.randomUUID();
        String admin = service.accessToken(service.member(tenant, "admin"));
        String email = "invitee-" + UUID.randomUUID().toString().substring(0, 10) + "@example.test";
        String password = new String(TestConfig.randomPassword());
        List<TestExchange> exchanges = new ArrayList<>();
        String token;
        Capture capture = new Capture();
        try (capture) {
            exchanges.add(service.post(BASE + "/invitations", Map.of("email", email, "role", "member"), bearer(admin)));
            token = service.invitations.tokenFor(email);
            exchanges.add(service.post(BASE + "/invitations/accept",
                    Map.of("tenantId", UUID.randomUUID().toString(), "token", token, "email", email,
                            "password", password)));
            exchanges.add(service.post(BASE + "/invitations/accept",
                    Map.of("tenantId", tenant.toString(), "token", token,
                            "email", "other-" + email, "password", password)));
            exchanges.add(service.post(BASE + "/invitations/accept",
                    Map.of("tenantId", tenant.toString(), "token", token, "email", email, "password", "x")));
            exchanges.add(service.post(BASE + "/invitations/accept",
                    Map.of("tenantId", tenant.toString(), "token", token, "email", email, "password", password)));
            exchanges.add(service.post(BASE + "/invitations/accept",
                    Map.of("tenantId", tenant.toString(), "token", token, "email", email, "password", password)));
            exchanges.add(service.post(BASE + "/login", Map.of("email", email, "password", password)));
        }

        assertThat(exchanges.get(0).code()).isEqualTo(201);
        assertThat(exchanges.get(4).code()).isEqualTo(201);
        assertThat(exchanges.get(5).code()).isEqualTo(400);
        assertThat(exchanges.get(6).code()).isEqualTo(200);
        for (String form : forms(token)) {
            assertThat(capture.text()).as("log and console output").doesNotContain(form);
            for (TestExchange exchange : exchanges) {
                assertThat(exchange.body()).as("response body").doesNotContain(form);
                for (String header : List.of("Location", "Set-Cookie", "Content-Type", "Cache-Control")) {
                    String value = exchange.header(header);
                    assertThat(value == null ? "" : value).as(header).doesNotContain(form);
                }
            }
        }
    }

    @Test
    @DisplayName("the issue response names the invitation and its tenant, address, role and expiry, and no token")
    void issueResponseCarriesNoToken() {
        UUID tenant = UUID.randomUUID();
        String admin = service.accessToken(service.member(tenant, "admin"));
        String email = "invitee-" + UUID.randomUUID().toString().substring(0, 10) + "@example.test";

        TestExchange issued = service.post(BASE + "/invitations", Map.of("email", email, "role", "member"), bearer(admin));

        assertThat(issued.code()).isEqualTo(201);
        var names = new ArrayList<String>();
        json(issued).propertyNames().forEach(names::add);
        assertThat(names).containsExactlyInAnyOrder("invitationId", "tenantId", "email", "role", "expiresAt");
        assertThat(service.invitations.tokenFor(email)).isNotBlank();
    }

    @Test
    @DisplayName("the text form of a notice and of an issued invitation leaves the token out")
    void textFormsLeaveTheTokenOut() {
        String token = "inv_" + TestConfig.randomBase64(24);
        InvitationNotice notice = new InvitationNotice(UUID.randomUUID(), UUID.randomUUID(), "a@example.test",
                "member", Instant.now(), token);

        assertThat(notice.toString()).doesNotContain(token).doesNotContain(token.substring(4));
        eu.exeris.caps.invitations.api.model.Invitation invitation = new eu.exeris.caps.invitations.api.model.Invitation(
                UUID.randomUUID(), UUID.randomUUID(), "a@example.test", "member", UUID.randomUUID(),
                Instant.now(), Instant.now().plusSeconds(60), null, null);
        assertThat(new eu.exeris.caps.invitations.api.model.IssuedInvitation(token, invitation).toString())
                .doesNotContain(token);
        assertThat(service.invitations.toString()).doesNotContain(token);
    }
}
