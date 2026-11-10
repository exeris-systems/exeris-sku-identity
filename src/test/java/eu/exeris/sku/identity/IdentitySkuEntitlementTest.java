package eu.exeris.sku.identity;

import eu.exeris.kernel.spi.contract.EntitlementClass;
import eu.exeris.kernel.spi.contract.EntitlementRequirement;
import eu.exeris.kernel.tck.contract.AbstractEntitlementRequirementTck;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.ServiceLoader;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("exeris-sku-identity: EntitlementRequirement")
class IdentitySkuEntitlementTest extends AbstractEntitlementRequirementTck {

    @Override
    protected Class<? extends EntitlementRequirement> providerClass() {
        return IdentitySkuEntitlement.class;
    }

    @Test
    @DisplayName("ServiceLoader discovers the provider from the cap's own service registration")
    void serviceLoaderDiscoversTheProvider() {
        List<Class<? extends EntitlementRequirement>> types = ServiceLoader.load(EntitlementRequirement.class)
                .stream()
                .map(ServiceLoader.Provider::type)
                .toList();

        assertThat(types).contains(IdentitySkuEntitlement.class);
    }

    @Test
    @DisplayName("It requires exactly this cap's own capability identifier")
    void requiresOnlyItsOwnCapability() {
        assertThat(new IdentitySkuEntitlement().requiredCapabilities()).containsExactly("exeris-sku-identity");
        assertThat(IdentitySkuEntitlement.CAPABILITY_ID).isEqualTo("exeris-sku-identity");
    }

    @Test
    @DisplayName("It is a commercial entitlement")
    void isCommercial() {
        assertThat(new IdentitySkuEntitlement().entitlementClass()).isEqualTo(EntitlementClass.COMMERCIAL);
    }
}
