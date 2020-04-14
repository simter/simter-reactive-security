package tech.simter.reactive.security.moduleauthorizer

import io.mockk.every
import io.mockk.impl.annotations.RelaxedMockK
import io.mockk.junit5.MockKExtension
import io.mockk.mockk
import io.mockk.verify
import org.assertj.core.api.Assertions.assertThat
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

  @ParameterizedTest
  @ValueSource(strings = ["", "AuthorizerName,OperationName"])
  fun `default deny message`(result: String) {
    // mock
    val operationKey = UUID.randomUUID().toString()
    val s = result.split(",")
    val authorizerName = s[0]
    val operationName = if (s.size > 1) s[1] else operationKey
    val properties = mockk<ModuleAuthorizeProperties>(relaxed = true) {
      every { operations[operationKey] } returns OperationAuthorizeProperties(
        roles = listOf(operationKey), name = operationName
      )
      every { name } returns authorizerName
    }
    every { securityService.verifyHasAnyRole(operationKey) } returns Mono.error(PermissionDeniedException())

    // invoke and verify
    ModuleAuthorizer.create(
      properties = properties,
      securityService = securityService
    ).verifyHasPermission(operationKey)
      .test()
      .consumeErrorWith {
        val msg = "Permission denied on $authorizerName $operationName"
        assertThat(it).isInstanceOf(PermissionDeniedException::class.java).hasMessage(msg)
      }
      .verify()
    verify {
      properties.operations[operationKey]
      securityService.verifyHasAnyRole(operationKey)
    }
  }

  @ParameterizedTest
  @ValueSource(strings = ["", "AuthorizerName,OperationName"])
  fun `custom deny message`(result: String) {
    // mock
    val operationKey = UUID.randomUUID().toString()
    val s = result.split(",")
    val authorizerName = s[0]
    val operationName = if (s.size > 1) s[1] else operationKey
    val properties = mockk<ModuleAuthorizeProperties>(relaxed = true) {
      every { operations[operationKey] } returns OperationAuthorizeProperties(
        roles = listOf(operationKey), name = operationName
      )
      every { name } returns authorizerName
    }
    every { securityService.verifyHasAnyRole(operationKey) } returns Mono.error(PermissionDeniedException())

    // invoke and verify
    ModuleAuthorizer.create(
      properties = properties,
      securityService = securityService,
      denyMessage = "A %1\$s B %2\$s C"
    ).verifyHasPermission(operationKey)
      .test()
      .consumeErrorWith {
        val msg = "A $authorizerName B $operationName C"
        assertThat(it).isInstanceOf(PermissionDeniedException::class.java).hasMessage(msg)
      }
      .verify()
    verify {
      properties.operations[operationKey]
      securityService.verifyHasAnyRole(operationKey)
    }
  }
}