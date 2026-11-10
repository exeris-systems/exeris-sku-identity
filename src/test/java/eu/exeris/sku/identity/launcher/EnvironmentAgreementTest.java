package eu.exeris.sku.identity.launcher;

import eu.exeris.sku.identity.config.IdentityConfigException;
import eu.exeris.sku.identity.support.TestConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("The kernel's environment property and the declared environment agree")
class EnvironmentAgreementTest {

    private static final String PROPERTY = "exeris.environment";

    private String saved;

    @BeforeEach
    void remember() {
        saved = System.getProperty(PROPERTY);
    }

    @AfterEach
    void restore() {
        if (saved == null) {
            System.clearProperty(PROPERTY);
        } else {
            System.setProperty(PROPERTY, saved);
        }
    }

    private static StartupPlan plan(String environment) {
        Map<String, String> env = new HashMap<>(TestConfig.env());
        env.put("EXERIS_DATABASE_URL", "jdbc:postgresql://db.example.test:5432/identity");
        env.put("EXERIS_DATABASE_USER", "identity_service");
        env.put("EXERIS_DATABASE_PASSWORD", TestConfig.randomBase64(12));
        env.put("EXERIS_ENVIRONMENT", environment);
        return StartupPlan.prepare(env);
    }

    @Test
    @DisplayName("the same environment written in another case or with blanks is accepted")
    void equalEnvironmentsAgree() {
        StartupPlan plan = plan("staging");
        for (String written : new String[]{"staging", "STAGING", " Staging "}) {
            System.setProperty(PROPERTY, written);
            assertThatCode(() -> IdentitySkuApplication.requireSameEnvironment(plan)).doesNotThrowAnyException();
        }
        System.clearProperty(PROPERTY);
        assertThatCode(() -> IdentitySkuApplication.requireSameEnvironment(plan)).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("a different or unknown environment is refused")
    void differentEnvironmentsAreRefused() {
        StartupPlan plan = plan("staging");
        for (String written : new String[]{"production", "PRODUCTION", "stagin"}) {
            System.setProperty(PROPERTY, written);
            assertThatThrownBy(() -> IdentitySkuApplication.requireSameEnvironment(plan))
                    .isInstanceOf(IdentityConfigException.class)
                    .satisfies(e -> assertThat(e.getMessage()).contains("disagrees"));
        }
    }
}
