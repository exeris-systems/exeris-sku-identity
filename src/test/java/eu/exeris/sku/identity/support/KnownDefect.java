package eu.exeris.sku.identity.support;

import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a test that states what the code must do and that the code does not do yet. It runs only when the
 * system property {@code identity.knownDefects} is {@code true}, so the build stays green while the defect is
 * open and the test fails, with the evidence in its assertion, when it is switched on.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@EnabledIfSystemProperty(named = "identity.knownDefects", matches = "true")
public @interface KnownDefect {

    /** The defect, in one line: what is expected and what the code does instead. */
    String value();
}
