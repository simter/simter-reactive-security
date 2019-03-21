package tech.simter.reactive.security

import reactor.core.publisher.Mono
import tech.simter.exception.PermissionDeniedException
import tech.simter.exception.UnauthenticatedException
import tech.simter.reactive.security.properties.LogicStrategy
import tech.simter.reactive.security.properties.ModuleAuthorizeProperties
import tech.simter.reactive.security.properties.OperationAuthorizeProperties
import tech.simter.reactive.security.properties.PermissionStrategy

/**
 * The module authorizer.
 *
 * The common usage is base on `module.authorization.$simterModule` config.
 * @author RJ
 */
interface ModuleAuthorizer {
  /**
   * Determine whether the system-context has permission to do the specific [operation].
   *
   * Return `Mono.just(true)` if has a authenticated system-context and it has permission to do the specific [operation],
   * otherwise return `Mono.just(false)`.
   */
  fun hasPermission(operation: String): Mono<Boolean>

  /**
   * Verify whether the system-context has permission to do the specific [operation].
   *
   * Return a [Mono.error] with [UnauthenticatedException] if without a authenticated system-context.
   * Or return a [Mono.error] with [PermissionDeniedException] if has a authenticated system-context but it has'ont permission to do the specific [operation].
   * Otherwise return [Mono.empty].
   */
  fun verifyHasPermission(operation: String): Mono<Void>

  companion object {
    /** A [ModuleAuthorizer] allow anything */
    val ALLOWER: ModuleAuthorizer = object : ModuleAuthorizer {
      override fun hasPermission(operation: String): Mono<Boolean> {
        return Mono.just(true)
      }

      override fun verifyHasPermission(operation: String): Mono<Void> {
        return Mono.empty()
      }
    }

    /** A [ModuleAuthorizer] deny anything */
    val DENIER: ModuleAuthorizer = object : ModuleAuthorizer {
      override fun hasPermission(operation: String): Mono<Boolean> {
        return Mono.just(false)
      }

      override fun verifyHasPermission(operation: String): Mono<Void> {
        return Mono.error(PermissionDeniedException())
      }
    }

    /**
     * Create a [ModuleAuthorizer] instance through [properties] and [securityService].
     *
     * If the specific operation not config in [properties.operations][ModuleAuthorizeProperties.operations],
     * use [properties.defaultPermission][ModuleAuthorizeProperties.defaultPermission] as default behavior.
     *
     * Otherwise estimate the operation permission by :
     * 1. [securityService.hasAnyRole(roles)][ReactiveSecurityService.hasAnyRole] if [operation.strategy][OperationAuthorizeProperties.strategy] is [LogicStrategy.Or].
     * 2. [securityService.hasAllRole(roles)][ReactiveSecurityService.hasAllRole] if [operation.strategy][OperationAuthorizeProperties.strategy] is [LogicStrategy.And].
     */
    fun create(properties: ModuleAuthorizeProperties, securityService: ReactiveSecurityService)
      : ModuleAuthorizer = object : ModuleAuthorizer {
      override fun hasPermission(operation: String): Mono<Boolean> {
        return properties.operations[operation]?.run {
          when (strategy) {
            LogicStrategy.Or -> securityService.hasAnyRole(*roles.toTypedArray())
            LogicStrategy.And -> securityService.hasAllRole(*roles.toTypedArray())
          }
        } ?: when (properties.defaultPermission) {
          PermissionStrategy.Allow -> Mono.just(true)
          PermissionStrategy.Deny -> Mono.just(false)
        }
      }

      override fun verifyHasPermission(operation: String): Mono<Void> {
        return properties.operations[operation]?.run {
          when (strategy) {
            LogicStrategy.Or -> securityService.verifyHasAnyRole(*roles.toTypedArray())
            LogicStrategy.And -> securityService.verifyHasAllRole(*roles.toTypedArray())
          }.onErrorMap { PermissionDeniedException("Verify has '$operation' permission failed", it) }
        } ?: when (properties.defaultPermission) {
          PermissionStrategy.Allow -> Mono.empty()
          PermissionStrategy.Deny -> Mono.error(PermissionDeniedException(
            "Verify has '$operation' permission failed because without config and default deny"))
        }
      }
    }
  }
}