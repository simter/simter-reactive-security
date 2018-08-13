package tech.simter.reactive.security

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig
import reactor.test.StepVerifier
import tech.simter.exception.PermissionDeniedException
import tech.simter.exception.UnauthenticatedException
import tech.simter.reactive.context.SystemContext.DataHolder
import tech.simter.reactive.context.SystemContext.SYSTEM_CONTEXT_KEY
import tech.simter.reactive.context.SystemContext.User
import java.util.*

@SpringJUnitConfig(ReactiveSecurityServiceImpl::class)
class ReactiveSecurityServiceTest @Autowired constructor(
  private val securityService: ReactiveSecurityService
) {
  @Test
  fun getAuthenticatedUser_Success() {
    val mono = securityService.getAuthenticatedUser()
      .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }

    StepVerifier.create(mono)
      .expectNext(Optional.of(DEFAULT_USER))
      .verifyComplete()
  }

  @Test
  fun getAuthenticatedUser_WithoutSystemContext() {
    val mono = securityService.getAuthenticatedUser()

    StepVerifier.create(mono)
      .expectNext(Optional.empty())
      .verifyComplete()
  }

  @Test
  fun hasAnyRole_Success() {
    // one roles
    StepVerifier.create(
      securityService.hasAnyRole("ADMIN")
        .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }
    )
      .expectNext(true)
      .verifyComplete()

    // two roles
    StepVerifier.create(
      securityService.hasAnyRole("NOT_EXISTS", "ADMIN")
        .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }
    )
      .expectNext(true)
      .verifyComplete()
  }

  @Test
  fun hasAnyRole_FailedByWithoutRole() {
    StepVerifier.create(securityService.hasAnyRole("NOT_EXISTS"))
      .expectNext(false)
      .verifyComplete()
  }

  @Test
  fun hasAnyRole_FailedByWithoutSystemContext() {
    StepVerifier.create(securityService.hasAnyRole("ADMIN"))
      .expectNext(false)
      .verifyComplete()
  }

  @Test
  fun hasAllRole_Success() {
    // one roles
    StepVerifier.create(
      securityService.hasAllRole("ADMIN")
        .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }
    )
      .expectNext(true)
      .verifyComplete()

    // two roles
    StepVerifier.create(
      securityService.hasAllRole("COMMON", "ADMIN")
        .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }
    )
      .expectNext(true)
      .verifyComplete()
  }

  @Test
  fun hasAllRole_FailedByWithoutRole() {
    // one roles
    StepVerifier.create(securityService.hasAllRole("NOT_EXISTS"))
      .expectNext(false)
      .verifyComplete()

    // two roles
    StepVerifier.create(securityService.hasAllRole("NOT_EXISTS", "ADMIN"))
      .expectNext(false)
      .verifyComplete()
  }

  @Test
  fun hasAllRole_FailedByWithoutSystemContext() {
    StepVerifier.create(securityService.hasAllRole("ADMIN"))
      .expectNext(false)
      .verifyComplete()
  }

  @Test
  fun verifyHasAnyRole_Success() {
    // one roles
    StepVerifier.create(
      securityService.verifyHasAnyRole("ADMIN")
        .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }
    ).verifyComplete()

    // two roles
    StepVerifier.create(
      securityService.verifyHasAnyRole("COMMON", "ADMIN")
        .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }
    ).verifyComplete()
  }

  @Test
  fun verifyHasAnyRole_ErrorWithUnauthenticated() {
    StepVerifier.create(securityService.verifyHasAnyRole("ANY"))
      .expectError(UnauthenticatedException::class.java)
      .verify()
  }

  @Test
  fun verifyHasAnyRole_ErrorWithPermissionDenied() {
    StepVerifier.create(
      securityService.verifyHasAnyRole("NOT_EXISTS")
        .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }
    )
      .expectError(PermissionDeniedException::class.java)
      .verify()
  }

  @Test
  fun verifyHasAllRole_Success() {
    // one roles
    StepVerifier.create(
      securityService.verifyHasAllRole("ADMIN")
        .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }
    ).verifyComplete()

    // two roles
    StepVerifier.create(
      securityService.verifyHasAllRole("COMMON", "ADMIN")
        .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }
    ).verifyComplete()
  }

  @Test
  fun verifyHasAllRole_ErrorWithUnauthenticated() {
    StepVerifier.create(securityService.verifyHasAllRole("ANY"))
      .expectError(UnauthenticatedException::class.java)
      .verify()
  }

  @Test
  fun verifyHasAllRole_ErrorWithPermissionDenied() {
    StepVerifier.create(
      securityService.verifyHasAllRole("NOT_EXISTS")
        .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }
    )
      .expectError(PermissionDeniedException::class.java)
      .verify()
  }

  companion object {
    private val DEFAULT_ROLES = listOf("ADMIN", "COMMON", "TESTER")
    val DEFAULT_USER = User(
      id = 0,
      account = "tester",
      name = "Tester"
    )
    val DEFAULT_SYSTEM_CONTEXT = DataHolder(
      user = DEFAULT_USER,
      roles = DEFAULT_ROLES
    )
  }
}