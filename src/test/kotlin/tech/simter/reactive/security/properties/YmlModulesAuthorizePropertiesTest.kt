package tech.simter.reactive.security.properties

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import tech.simter.reactive.security.properties.LogicStrategy.And
import tech.simter.reactive.security.properties.LogicStrategy.Or
import tech.simter.reactive.security.properties.PermissionStrategy.Allow
import tech.simter.reactive.security.properties.PermissionStrategy.Deny

/**
 * @author RJ
 */
@SpringBootTest(classes = [YmlModulesAuthorizePropertiesTest.Cfg::class])
class YmlModulesAuthorizePropertiesTest @Autowired constructor(
  private val modulesAuthorizer: ModulesAuthorizeProperties
) {
  @Configuration
  @EnableConfigurationProperties
  class Cfg {
    @Bean
    @ConfigurationProperties(prefix = "module.authorization.multiple-module")
    fun multipleModuleAuthorizeProperties(): ModulesAuthorizeProperties {
      return ModulesAuthorizeProperties()
    }
  }

  // see 'module.authorization.multiple-module'
  @Test
  fun test() {
    assertNotNull(modulesAuthorizer)
    assertEquals(2, modulesAuthorizer.modules.size)

    val m1 = modulesAuthorizer.modules["m1"] as ModuleAuthorizeProperties
    assertEquals(3, m1.operations.size)
    assertEquals(Allow, m1.defaultPermission)
    assertEquals(OperationAuthorizeProperties(strategy = Or, roles = listOf("X_READ1", "X_READ2")), m1.operations["read"])
    assertEquals(OperationAuthorizeProperties(strategy = And, roles = listOf("X_CREAT", "X_UPDATE")), m1.operations["create"])
    assertEquals(OperationAuthorizeProperties(strategy = Or, roles = listOf("X_DELETE")), m1.operations["delete"])

    val m2 = modulesAuthorizer.modules["m2"] as ModuleAuthorizeProperties
    assertEquals(3, m2.operations.size)
    assertEquals(Deny, m2.defaultPermission)
    assertEquals(OperationAuthorizeProperties(strategy = Or, roles = listOf("Y_READ1", "Y_READ2")), m2.operations["read"])
    assertEquals(OperationAuthorizeProperties(strategy = Or, roles = listOf("Y_CREAT", "Y_UPDATE")), m2.operations["create"])
    assertEquals(OperationAuthorizeProperties(strategy = Or, roles = listOf("Y_DELETE")), m2.operations["delete"])
  }
}