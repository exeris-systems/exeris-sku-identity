package eu.exeris.sku.identity;

import eu.exeris.kernel.spi.contract.EntitlementClass;
import eu.exeris.kernel.spi.contract.EntitlementRequirement;

import java.util.Set;

/**
 * Declares that production execution of {@code exeris-sku-identity} needs a commercial entitlement
 * (ADR-023 {@code commercial}, ADR-089).
 *
 * <p>Registered in {@code META-INF/services/eu.exeris.kernel.spi.contract.EntitlementRequirement}, so the
 * kernel's Phase 0 contract gate discovers it before any subsystem starts. The composed commercial
 * capabilities register their own requirements the same way; a licence manifest entitles the SKU and each
 * of them under its own identifier.
 */
public final class IdentitySkuEntitlement implements EntitlementRequirement {

    /**
     * Identifier a license manifest lists in {@code entitlement.capabilities} to entitle this SKU:
     * the SKU's Maven artifactId, which is its identity in the ecosystem.
     */
    public static final String CAPABILITY_ID = "exeris-sku-identity";

    private static final Set<String> REQUIRED = Set.of(CAPABILITY_ID);

    /** ServiceLoader constructor. */
    public IdentitySkuEntitlement() {
        // stateless
    }

    @Override
    public Set<String> requiredCapabilities() {
        return REQUIRED;
    }

    @Override
    public EntitlementClass entitlementClass() {
        return EntitlementClass.COMMERCIAL;
    }
}
