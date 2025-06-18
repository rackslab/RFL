# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

### Added
- auth: Allow rebind connection with service bind credentials after successful
  user authentication to retrieve user information and groups (#57).
  Contribution from @Cornelicorn.

## [1.4.0] - 2025-04-11

### Added
- log:
  - Support de-facto standard `NO_COLOR` environment variable by disabling ANSI
    colors when this variable is set with non-empty value (#45).
  - Support optional logger component used as prefix of every log entries.
- settings: Support parameters deprecation (#48).
- auth:
  - Introduce `JWTBaseManager` for more generic and versatile JWT encode and
    decode management with custom claimset.
  - Introduce `jwt_validate_expiration()` function to load and validate
    expiration of JWT without its signature.

### Changed
- log: Disable debug by default with `DaemonFormatter` similarly to
  `TTYFormatter`.

### Fixed
- auth:
  - Catch `ldap.OPERATIONS_ERROR` on LDAP users list and user DN lookup
    searches (#40).
  - Support binary non-ascii JWT private signature key by default with option to
    expect text key.

## [1.3.0] - 2025-02-03

### Added
- auth:
  - Introduce `AnonymousUser` class as a child of `AuthenticatedUser` with
    `is_anonynous()` on `AuthenticatedUser` class to tell if user is anonymous.
  - Add posibility to lookup user DN in the scope of user base subtree before
    trying authentication instead of expecting the DN is the basic concatenation
    of the user name attribute, the login and the user base (#30→#36).
- perms: Add `RBACPolicyManager.disable_anonymous()` as a mean to disable
  anonymous role even if defined in loaded authorization policy (#35→#39)

### Changed
- web: Change error description and log message when unauthorized to access
  endpoint with `@rbac_action` decorator with anonymous token in order to match
  access without token.

### Fixed
- perms: Fix retrieval of anonymous user permissions as defined in authorization
  policy (#29→#31).
- web:
  - Deny access without bearer token in `@check_jwt` and `@rbac_action`
    decorators (#33,#37→#34,#38).
  - Add missing dependency on Flask package.

## [1.2.0] - 2024-11-26

### Added
- settings: print list parameters as comma-separated list of values for more
  readability (#27).

### Changed
- permissions: Do not attribute anonymous role by default anymore to
  authenticated users.

### Fixed
- core: `AttributeError` with `asyncio.tasks._gather` on Python 3.6 (#23).
- settings:
  - Print URL as readable string in dumps (#25).
  - Print IP/network addresses as readable strings in dumps (#26).

## [1.1.1] - 2024-11-05

### Added
- web: Add warning log entry in case of JWT decode error.

### Fixed
- settings: Valid ip and network default values were wrongly reported having the
  wrong type.

## [1.1.0] - 2024-10-18

### Added
- core: Introduce `asyncio` module with `asyncio_run()` wrapper with a
  backported version of `asyncio.run()` compatible with Python 3.6 (#11).
- settings:
  - Add `dump()` method on `RuntimeSettings` class to print all settings with
    their value and origin on standard output.
  - Add `name` attribute on `SettingsDefinitionLoaderYaml` and
    `RuntimeSettingsSiteLoaderIni` classes.
  - Add `_origin` dict attribute on `RuntimeSettingsSection` to keep tracks of
    origin of parameters values.
  - Support new `password` type of parameters, similar to strings but it is not
    printed as clear text when dumped (#7).
  - Support new `ip` and `network` types of parameters which return Python
    `ipaddress.IPv{4,6}Address` and `ipaddress.IPv{4,6}Network` objects
    respectively (#8).

### Fixed
- auth: When retrieving users with `users()` method, raise
  `LDAPAuthenticationError` only when user name attribute is missing in all
  retrieved user entries, instead of raising as soon as it is missing in any
  user entry. Warning log message is emitted for all user entries that miss the
  attribute (#12).

## [1.0.3] - 2024-08-30

### Added
- core: Introduce `utils` module with `shlex_join` function to backport
  `shlex.join()` from Python >= 3.8.
- auth:
  - Add `user_primary_group_attribute` argument to `LDAPAuthentifier` class
    initializer with default value _gidNumber_ to define an alternative
    user primary group ID attribute (#4).
  - Add `group_object_classes` argument to `LDAPAuthentifier` class
    initializer with default values _posixGroup_ and _groupOfNames_ to define
    alternative LDAP group object classes (#6).

### Changed
- auth: Support absence of primary group attribute optional in LDAP user
  entries (#5).

### Fixed
- auth: Handle `UnicodeDecodeError` when loading JWT private key (#3).

## [1.0.2] - 2024-06-19

### Added
- auth: Add `user_name_attribute` argument with default value _uid_ to
  `LDAPAuthentifier` class initializer to specify an alternative user name
  attribute (#2).
- build: Support explicit packages list without find, lack of dependencies, lack
  of urls, lack and file license in PEP 518 → setup.py script generator.

### Changed
- auth: Add default values for `cacert`, `user_class`, `user_fullname_attribute`
  and `group_name_attribute` arguments of `LDAPAuthentifier` class initializer.

## [1.0.1] - 2024-05-08

### Changed
- pkgs: add `project` and `build-system` sections in main `pyproject.toml` to
  satisfy requirements of packaging build systems.

## [1.0.0] - 2024-04-08

[unreleased]: https://github.com/rackslab/RFL/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/rackslab/RFL/releases/tag/v1.4.0
[1.3.0]: https://github.com/rackslab/RFL/releases/tag/v1.3.0
[1.2.0]: https://github.com/rackslab/RFL/releases/tag/v1.2.0
[1.1.1]: https://github.com/rackslab/RFL/releases/tag/v1.1.1
[1.1.0]: https://github.com/rackslab/RFL/releases/tag/v1.1.0
[1.0.3]: https://github.com/rackslab/RFL/releases/tag/v1.0.3
[1.0.2]: https://github.com/rackslab/RFL/releases/tag/v1.0.2
[1.0.1]: https://github.com/rackslab/RFL/releases/tag/v1.0.1
[1.0.0]: https://github.com/rackslab/RFL/releases/tag/v1.0.0
