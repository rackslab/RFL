# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- core: Introduce `utils` module with `shlex_join` function to backport
  `shlex.join()` from Python >= 3.8.
- auth: Add `user_primary_group_attribute` argument with default value
  _gidNumber_ to `LDAPAuthentifier` class initializer to specify an alternative
  user primary group ID attribute (#4).

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

[unreleased]: https://github.com/rackslab/RFL/compare/v1.0.2...HEAD
[1.0.2]: https://github.com/rackslab/RFL/releases/tag/v1.0.2
[1.0.1]: https://github.com/rackslab/RFL/releases/tag/v1.0.1
[1.0.0]: https://github.com/rackslab/RFL/releases/tag/v1.0.0
