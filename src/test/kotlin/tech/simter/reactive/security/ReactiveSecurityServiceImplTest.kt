package tech.simter.reactive.security

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig
import reactor.kotlin.test.test
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
    securityService.getAuthenticatedUser()
      .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }
      .test()
      .expectNext(Optional.of(DEFAULT_USER))
      .verifyComplete()
  }

  @Test
  fun getAuthenticatedUser_WithoutSystemContext() {
    securityService.getAuthenticatedUser()
      .test()
      .expectNext(Optional.empty())
      .verifyComplete()
  }

  @Test
  fun hasAnyRole_Success() {
    // one roles
    securityService.hasAnyRole("ADMIN")
      .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }
      .test()
      .expectNext(true)
      .verifyComplete()

    // two roles
    securityService.hasAnyRole("NOT_EXISTS", "ADMIN")
      .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }
      .test()
      .expectNext(true)
      .verifyComplete()
  }

  @Test
  fun hasAnyRole_FailedByWithoutRole() {
    securityService.hasAnyRole("NOT_EXISTS")
      .test()
      .expectNext(false)
      .verifyComplete()
  }

  @Test
  fun hasAnyRole_FailedByWithoutSystemContext() {
    securityService.hasAnyRole("ADMIN")
      .test()
      .expectNext(false)
      .verifyComplete()
  }

  @Test
  fun hasAllRole_Success() {
    // one roles
    securityService.hasAllRole("ADMIN")
      .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }
      .test()
      .expectNext(true)
      .verifyComplete()

    // two roles
    securityService.hasAllRole("COMMON", "ADMIN")
      .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }
      .test()
      .expectNext(true)
      .verifyComplete()
  }

  @Test
  fun hasAllRole_FailedByWithoutRole() {
    // one roles
    securityService.hasAllRole("NOT_EXISTS")
      .test()
      .expectNext(false)
      .verifyComplete()

    // two roles
    securityService.hasAllRole("NOT_EXISTS", "ADMIN")
      .test()
      .expectNext(false)
      .verifyComplete()
  }

  @Test
  fun hasAllRole_FailedByWithoutSystemContext() {
    securityService.hasAllRole("ADMIN")
      .test()
      .expectNext(false)
      .verifyComplete()
  }

  @Test
  fun verifyHasAnyRole_Success() {
    // one roles
    securityService.verifyHasAnyRole("ADMIN")
      .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }
      .test()
      .verifyComplete()

    // two roles
    securityService.verifyHasAnyRole("COMMON", "ADMIN")
      .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }
      .test()
      .verifyComplete()
  }

  @Test
  fun verifyHasAnyRole_ErrorWithUnauthenticated() {
    securityService.verifyHasAnyRole("ANY")
      .test()
      .expectError(UnauthenticatedException::class.java)
      .verify()
  }

  @Test
  fun verifyHasAnyRole_ErrorWithPermissionDenied() {
    securityService.verifyHasAnyRole("NOT_EXISTS")
      .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }
      .test()
      .expectError(PermissionDeniedException::class.java)
      .verify()
  }

  @Test
  fun verifyHasAllRole_Success() {
    // one roles
    securityService.verifyHasAllRole("ADMIN")
      .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }
      .test().verifyComplete()

    // two roles
    securityService.verifyHasAllRole("COMMON", "ADMIN")
      .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }
      .test()
      .verifyComplete()
  }

  @Test
  fun verifyHasAllRole_ErrorWithUnauthenticated() {
    securityService.verifyHasAllRole("ANY")
      .test()
      .expectError(UnauthenticatedException::class.java)
      .verify()
  }

  @Test
  fun verifyHasAllRole_ErrorWithPermissionDenied() {
    securityService.verifyHasAllRole("NOT_EXISTS")
      .subscriberContext { it.put(SYSTEM_CONTEXT_KEY, DEFAULT_SYSTEM_CONTEXT) }
      .test()
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