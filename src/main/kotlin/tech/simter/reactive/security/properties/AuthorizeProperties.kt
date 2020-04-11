/**
 * @author RJ
 */
package tech.simter.reactive.security.properties

import tech.simter.reactive.security.properties.LogicStrategy.And
import tech.simter.reactive.security.properties.LogicStrategy.Or
import tech.simter.reactive.security.properties.PermissionStrategy.Allow
import tech.simter.reactive.security.properties.PermissionStrategy.Deny

/**
 * The module authorize properties.
 *
 * YML file config sample:
 *
 * ```
 * module.authorization.simter-kv:
 *   defaultPermission: "Allow"
 *   operations:
 *     read:
 *       roles: ["X_READ1", "X_READ2"]
 *       strategy: 'or'
 *     create:
 *       roles: ["X_CREAT", "X_UPDATE"]
 *       strategy: "and"
 *     delete:
 *       roles: ["X_DELETE"]
 * ```
 */
data class ModuleAuthorizeProperties(
  /**
   * All config operations.
   *
   *  The key is the operation identity, such as 'read', 'delete'.
   */
  val operations: Map<String, OperationAuthorizeProperties> = HashMap(),
  /**
   * The default permission behavior for the operation not config in [operations].
   *
   * The value could be [Deny] or [Allow], default value is [Deny]
   */
  var defaultPermission: PermissionStrategy = Deny,
  /**
   * The label for describe the authorizer.
   *
   * Default value is a empty string.
   */
  var name: String = ""
)

/**
 * The operation authorize properties.
 */
data class OperationAuthorizeProperties(
  /** All config roles */
  val roles: List<String> = mutableListOf(),
  /**
   * The roles merge strategy.
   *
   * The value could be [Or] or [And], default value is [Or].
   */
  var strategy: LogicStrategy = Or,
  /**
   * The label for describe the operation.
   *
   * Default value is a empty string.
   */
  var name: String = ""
)

/**
 * The logic strategy for roles merge.
 */
enum class LogicStrategy { Or, And }

/**
 * The permission strategy for module or operation.
 */
enum class PermissionStrategy { Allow, Deny }