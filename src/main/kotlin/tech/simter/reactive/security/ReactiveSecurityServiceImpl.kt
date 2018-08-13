package tech.simter.reactive.security

import org.springframework.stereotype.Service
import reactor.core.publisher.Mono
import tech.simter.reactive.context.SystemContext
import java.util.*

/**
 * The default reactive security service implement.
 *
 * It use the [SystemContext] to do the default implement.
 *
 * @author RJ
 */
@Service
class ReactiveSecurityServiceImpl : ReactiveSecurityService {
  override fun getAuthenticatedUser(): Mono<Optional<SystemContext.User>> {
    return SystemContext.getAuthenticatedUser()
  }

  override fun hasAnyRole(vararg roles: String): Mono<Boolean> {
    return SystemContext.hasAnyRole(*roles)
  }

  override fun hasAllRole(vararg roles: String): Mono<Boolean> {
    return SystemContext.hasAllRole(*roles)
  }

  override fun verifyHasAnyRole(vararg roles: String): Mono<Void> {
    return SystemContext.verifyHasAnyRole(*roles)
  }

  override fun verifyHasAllRole(vararg roles: String): Mono<Void> {
    return SystemContext.verifyHasAllRole(*roles)
  }
}