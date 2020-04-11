package tech.simter.reactive.security.moduleauthorizer

import io.mockk.every
import io.mockk.impl.annotations.RelaxedMockK
import io.mockk.junit5.MockKExtension
import io.mockk.verify
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
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

@ExtendWith(MockKExtension::class)
class VerifyHasPermissionMethodImplTest constructor(
  @RelaxedMockK val properties: ModuleAuthorizeProperties,
  @RelaxedMockK val securityService: ReactiveSecurityService
) {
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
    // mock
    val passed = result.toBoolean()
    val operation = UUID.randomUUID().toString()
    every { properties.operations[operation] } returns null                    // without operations config
    every { properties.defaultPermission } returns if (passed) Allow else Deny // default behavior

    // invoke and verify
    val test = ModuleAuthorizer.create(properties, securityService)
      .verifyHasPermission(operation)
      .test()
    if (passed) test.verifyComplete()
    else test.verifyError(PermissionDeniedException::class.java)
    verify(exactly = 1) {
      properties.operations[operation]
      properties.defaultPermission
    }
    verify(exactly = 0) {
      securityService.verifyHasAnyRole(operation)
    }
  }

  @ParameterizedTest
  @ValueSource(strings = ["true", "false"])
  fun `by roles logic or`(result: String) {
    // mock
    val passed = result.toBoolean()
    val operation = UUID.randomUUID().toString()
    every { properties.operations[operation] } returns OperationAuthorizeProperties(
      roles = listOf(operation), strategy = Or // logic or
    )
    every { securityService.verifyHasAnyRole(operation) } returns if (passed) Mono.empty() else Mono.error(PermissionDeniedException())

    // invoke and verify
    val test = ModuleAuthorizer.create(properties, securityService)
      .verifyHasPermission(operation)
      .test()
    if (passed) test.verifyComplete()
    else test.verifyError(PermissionDeniedException::class.java)
    verify(exactly = 1) {
      properties.operations[operation]
      securityService.verifyHasAnyRole(operation)
    }
  }

  @ParameterizedTest
  @ValueSource(strings = ["true", "false"])
  fun `by roles logic and`(result: String) {
    // mock
    val passed = result.toBoolean()
    val operation = UUID.randomUUID().toString()
    every { properties.operations[operation] } returns OperationAuthorizeProperties(
      roles = listOf(operation), strategy = And
    )
    every { securityService.verifyHasAllRole(operation) } returns if (passed) Mono.empty() else Mono.error(PermissionDeniedException())

    // invoke and verify
    val test = ModuleAuthorizer.create(properties, securityService)
      .verifyHasPermission(operation)
      .test()
    if (passed) test.verifyComplete()
    else test.verifyError(PermissionDeniedException::class.java)
    verify {
      properties.operations[operation]
      securityService.verifyHasAllRole(operation)
    }
  }
}