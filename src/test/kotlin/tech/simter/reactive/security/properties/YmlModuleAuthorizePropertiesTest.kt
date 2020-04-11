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

/**
 * @author RJ
 */
@SpringBootTest(classes = [YmlModuleAuthorizePropertiesTest.Cfg::class])
class YmlModuleAuthorizePropertiesTest @Autowired constructor(
  private val moduleAuthorizer: ModuleAuthorizeProperties
) {
  @Configuration
  @EnableConfigurationProperties
  class Cfg {
    @Bean
    @ConfigurationProperties(prefix = "simter-sample.authorization")
    fun moduleAuthorizer(): ModuleAuthorizeProperties {
      return ModuleAuthorizeProperties()
    }
  }

  // see 'module.authorization.simter-sample'
  @Test
  fun test() {
    assertNotNull(moduleAuthorizer)
    assertEquals(3, moduleAuthorizer.operations.size)
    assertEquals(Allow, moduleAuthorizer.defaultPermission)
    assertEquals(OperationAuthorizeProperties(strategy = Or, roles = listOf("X_READ1", "X_READ2")), moduleAuthorizer.operations["read"])
    assertEquals(OperationAuthorizeProperties(strategy = And, roles = listOf("X_CREATE", "X_UPDATE")), moduleAuthorizer.operations["create,update"])
    assertEquals(OperationAuthorizeProperties(strategy = Or, roles = listOf("X_DELETE")), moduleAuthorizer.operations["delete"])
  }
}