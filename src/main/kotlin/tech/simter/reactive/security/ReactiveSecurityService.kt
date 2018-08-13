package tech.simter.reactive.security

import reactor.core.publisher.Mono
import tech.simter.exception.PermissionDeniedException
import tech.simter.exception.UnauthenticatedException
import tech.simter.reactive.context.SystemContext.User
import java.util.*

/**
 * The reactive security service.
 *
 * @author RJ
 */
interface ReactiveSecurityService {
  /**
   * Get the authenticated user info.
   *
   * Return a mono instance with the authenticated user info if has a authenticated system-context,
   * otherwise return Mono.just([Optional.empty]).
   */
  fun getAuthenticatedUser(): Mono<Optional<User>>

  /**
   * Determine whether the system-context has any specified [roles].
   *
   * Return `Mono.just(true)` if has a authenticated system-context and it has any specified [roles],
   * otherwise return `Mono.just(false)`.
   */
  fun hasAnyRole(vararg roles: String): Mono<Boolean>

  /**
   * Determine whether the system-context has all specified [roles].
   *
   * Return `Mono.just(true)` if has a authenticated system-context and it has all specified [roles],
   * otherwise return `Mono.just(false)`.
   */
  fun hasAllRole(vararg roles: String): Mono<Boolean>

  /**
   * Verify whether the system-context has any specified [roles].
   *
   * Return a [Mono.error] with [UnauthenticatedException] if without a authenticated system-context.
   * Or return a [Mono.error] with [PermissionDeniedException] if has a authenticated system-context but it has'ont any specified [roles].
   * Otherwise return [Mono.empty].
   */
  fun verifyHasAnyRole(vararg roles: String): Mono<Void>

  /**
   * Verify whether the system-context has all specified [roles].
   *
   * Return a [Mono.error] with [UnauthenticatedException] if without a authenticated system-context.
   * Or return a [Mono.error] with [PermissionDeniedException] if has a authenticated system-context but it has'ont all specified [roles].
   * Otherwise return [Mono.empty].
   */
  fun verifyHasAllRole(vararg roles: String): Mono<Void>
}