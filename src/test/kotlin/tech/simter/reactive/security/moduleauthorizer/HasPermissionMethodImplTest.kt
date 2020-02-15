package tech.simter.reactive.security.moduleauthorizer

import io.mockk.confirmVerified
import io.mockk.every
import io.mockk.mockkClass
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import reactor.core.publisher.Mono
import reactor.kotlin.test.test
import tech.simter.reactive.security.ModuleAuthorizer
import tech.simter.reactive.security.ModuleAuthorizer.Companion.ALLOWER
import tech.simter.reactive.security.ModuleAuthorizer.Companion.DENIER
import tech.simter.reactive.security.ReactiveSecurityService
import tech.simter.reactive.security.properties.LogicStrategy.And
import tech.simter.reactive.security.properties.LogicStrategy.Or
import tech.simter.reactive.security.properties.ModuleAuthorizeProperties
import tech.simter.reactive.security.properties.OperationAuthorizeProperties
import tech.simter.reactive.security.properties.PermissionStrategy.Allow
import tech.simter.reactive.security.properties.PermissionStrategy.Deny
import java.util.*

class HasPermissionMethodImplTest {
  @Test
  fun `explicit allow anything`() {
    ALLOWER.hasPermission("any")
      .test()
      .expectNext(true)
      .verifyComplete()
  }

  @Test
  fun `explicit deny anything`() {
    DENIER.hasPermission("any")
      .test()
      .expectNext(false)
      .verifyComplete()
  }

  @ParameterizedTest
  @ValueSource(strings = ["true", "false"])
  fun `without operation config`(result: String) {
    val passed = result.toBoolean()
    val operation = UUID.randomUUID().toString()
    val properties = mockkClass(ModuleAuthorizeProperties::class) {
      every { operations[operation] } returns null                    // without operations config
      every { defaultPermission } returns if (passed) Allow else Deny // default behavior
    }
    val securityService = mockkClass(ReactiveSecurityService::class)
    val moduleAuthorizer = ModuleAuthorizer.create(properties, securityService)

    moduleAuthorizer.hasPermission(operation)
      .test()
      .expectNext(passed)
      .verifyComplete()

    verify(exactly = 1) {
      properties.operations[operation]
      properties.defaultPermission
    }
    confirmVerified(properties, securityService)
  }

  @ParameterizedTest //(name = "[{index}] passed={0}")
  @ValueSource(strings = ["true", "false"])
  fun `by roles logic or`(result: String) {
    val passed = result.toBoolean()
    val operation = UUID.randomUUID().toString()
    val properties = mockkClass(ModuleAuthorizeProperties::class) {
      every { operations[operation] } returns OperationAuthorizeProperties(
        roles = listOf(operation), strategy = Or // logic or
      )
    }
    val securityService = mockkClass(ReactiveSecurityService::class) {
      every { hasAnyRole(operation) } returns Mono.just(passed)
    }
    val moduleAuthorizer = ModuleAuthorizer.create(properties, securityService)

    moduleAuthorizer.hasPermission(operation)
      .test()
      .expectNext(passed)
      .verifyComplete()

    verify(exactly = 1) {
      properties.operations[operation]
      securityService.hasAnyRole(operation)
    }
    confirmVerified(properties, securityService)
  }

  @ParameterizedTest
  @ValueSource(strings = ["true", "false"])
  fun `by roles logic and`(result: String) {
    val passed = result.toBoolean()
    val operation = UUID.randomUUID().toString()
    val properties = mockkClass(ModuleAuthorizeProperties::class) {
      every { operations[operation] } returns OperationAuthorizeProperties(
        roles = listOf(operation), strategy = And // logic and
      )
    }
    val securityService = mockkClass(ReactiveSecurityService::class) {
      every { hasAllRole(operation) } returns Mono.just(passed)
    }
    val moduleAuthorizer = ModuleAuthorizer.create(properties, securityService)

    moduleAuthorizer.hasPermission(operation)
      .test()
      .expectNext(passed)
      .verifyComplete()

    verify(exactly = 1) {
      properties.operations[operation]
      securityService.hasAllRole(operation)
    }
    confirmVerified(properties, securityService)
  }
}