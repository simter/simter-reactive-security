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
import tech.simter.exception.PermissionDeniedException
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

class VerifyHasPermissionMethodImplTest {
  @Test
  fun `explicit allow anything`() {
    ALLOWER.verifyHasPermission("any")
      .test()
      .verifyComplete()
  }

  @Test
  fun `explicit deny anything`() {
    DENIER.verifyHasPermission("any")
      .test()
      .verifyError(PermissionDeniedException::class.java)
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

    val test = moduleAuthorizer.verifyHasPermission(operation).test()
    if (passed) test.verifyComplete()
    else test.verifyError(PermissionDeniedException::class.java)

    verify(exactly = 1) {
      properties.operations[operation]
      properties.defaultPermission
    }
    confirmVerified(properties, securityService)
  }

  @ParameterizedTest
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
      every { verifyHasAnyRole(operation) } returns if (passed) Mono.empty() else Mono.error(PermissionDeniedException())
    }
    val moduleAuthorizer = ModuleAuthorizer.create(properties, securityService)

    val test = moduleAuthorizer.verifyHasPermission(operation).test()
    if (passed) test.verifyComplete()
    else test.verifyError(PermissionDeniedException::class.java)

    verify(exactly = 1) {
      properties.operations[operation]
      securityService.verifyHasAnyRole(operation)
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
      every { verifyHasAllRole(operation) } returns if (passed) Mono.empty() else Mono.error(PermissionDeniedException())
    }
    val moduleAuthorizer = ModuleAuthorizer.create(properties, securityService)

    val test = moduleAuthorizer.verifyHasPermission(operation).test()
    if (passed) test.verifyComplete()
    else test.verifyError(PermissionDeniedException::class.java)

    verify(exactly = 1) {
      properties.operations[operation]
      securityService.verifyHasAllRole(operation)
    }
    confirmVerified(properties, securityService)
  }
}