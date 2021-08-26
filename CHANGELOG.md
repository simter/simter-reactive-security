# simter-reactive-security changelog

## 2.0.1 - 2021-08-26

- Fixed `verifyHasAnyPermission` and `verifyHasAllPermission` without error message when implements by `ModuleAuthorizer.create`

## 2.0.0 - 2020-11-19

- Upgrade to simter-dependencies-2.0.0

## 2.0.0-M1 - 2020-06-02

- Upgrade to simter-2.0.0-M1

## 1.2.0-M2 - 2020-04-15

- Support custom deny message for ModuleAuthorizer
- Support config a name for ModuleAuthorizer
- Upgrade to simter-1.3.0-M14

## 1.2.0-M1 - 2020-02-15

- Support multiple operations permission checking on ModuleAuthorizer [#1]
- Use reactor-kotlin-extensions to avoid deprecated warning
- Upgrade to simter-1.3.0-M13

[#1]: https://github.com/simter/simter-reactive-security/issues/1

## 1.1.1 - 2019-09-27

- Fixed kotlin compile config

## 1.1.0 - 2019-07-03

- Change parent to simter-dependencies-1.2.0
- Add ModuleAuthorizeProperties
- Add ModuleAuthorizer
- Simplify JUnit5 config

## 1.0.0 - 2019-01-08

- Add convenient method `hasRole(roleA, roleB, roleC) : Mono<Triple<Boolean, Boolean, Boolean>>`
- Add convenient method `hasRole(roleA, roleB) : Mono<Pair<Boolean, Boolean>>`

## 0.5.0 - 2018-08-13

- initial