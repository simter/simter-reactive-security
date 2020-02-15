package tech.simter.reactive.security.moduleauthorizer

import io.mockk.every
import io.mockk.spyk
import io.mockk.verify
import org.junit.jupiter.api.Test
import reactor.core.publisher.Mono
import reactor.kotlin.test.test
import tech.simter.exception.PermissionDeniedException
import tech.simter.reactive.security.ModuleAuthorizer
import tech.simter.reactive.security.ModuleAuthorizer.Companion.ALLOWER
import tech.simter.reactive.security.ModuleAuthorizer.Companion.DENIER
import java.util.*

class VerifyHasAllPermissionMethodImplTest {
  @Test
  fun `empty operations params`() {
    ALLOWER.verifyHasAllPermission()
      .test()
      .verifyError(IllegalArgumentException::class.java)

    DENIER.verifyHasAllPermission()
      .test()
      .verifyError(IllegalArgumentException::class.java)
  }

  @Test
  fun `explicit allow anything`() {
    ALLOWER.verifyHasAllPermission("any1", "any2")
      .test()
      .verifyComplete()
  }

  @Test
  fun `explicit deny anything`() {
    DENIER.verifyHasAllPermission("any1", "any2")
      .test()
      .verifyError(PermissionDeniedException::class.java)
  }

  @Test
  fun `multiple operations`() {
    val operation1 = UUID.randomUUID().toString()
    val operation2 = UUID.randomUUID().toString()

    data class Cfg(val operation: String, val hasPermission: Boolean, val exactly: Int)

    val defaultModuleAuthorizer = object : ModuleAuthorizer {
      override fun hasPermission(operation: String): Mono<Boolean> {
        TODO("not implemented1")
      }

      override fun verifyHasPermission(operation: String): Mono<Void> {
        TODO("not implemented")
      }
    }

    // test all cases with two operations
    listOf(
      Pair(Cfg(operation1, true, 1), Cfg(operation2, true, 1)),
      Pair(Cfg(operation1, true, 1), Cfg(operation2, false, 1)),
      Pair(Cfg(operation1, false, 1), Cfg(operation2, true, 0)),
      Pair(Cfg(operation1, false, 1), Cfg(operation2, false, 0))
    ).forEach { pair ->
      val spyModuleAuthorizer = spyk(defaultModuleAuthorizer) {
        every { hasPermission(pair.first.operation) } returns Mono.just(pair.first.hasPermission)
        every { hasPermission(pair.second.operation) } returns Mono.just(pair.second.hasPermission)
      }

      val test = spyModuleAuthorizer
        .verifyHasAllPermission(pair.first.operation, pair.second.operation)
        .test()
      if (pair.first.hasPermission && pair.second.hasPermission) {
        test.verifyComplete()
      } else {
        test.verifyError(PermissionDeniedException::class.java)
      }
      verify(exactly = pair.first.exactly) { spyModuleAuthorizer.hasPermission(pair.first.operation) }
      verify(exactly = pair.second.exactly) { spyModuleAuthorizer.hasPermission(pair.second.operation) }
    }
  }
}