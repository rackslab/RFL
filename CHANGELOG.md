# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unreleased]

### Added
- auth: Add `user_name_attribute` argumetn with default value _uid_ to
  `LDAPAuthentifier` class initializer to specify an alternative user name
  attribute (#2).
- build: Support explicit packages list without find in PEP 518 → setup.py
  script generator.

### Changed
- auth: Add default values for `cacert`, `user_class`, `user_fullname_attribute`
  and `group_name_attribute` arguments of `LDAPAuthentifier` class initializer.

## [1.0.1] - 2024-05-08

### Changed
- pkgs: add `project` and `build-system` sections in main `pyproject.toml` to
  satisfy requirements of packaging build systems.

## [1.0.0] - 2024-04-08

[unreleased]: https://github.com/rackslab/RFL/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/rackslab/RFL/releases/tag/v1.0.1
[1.0.0]: https://github.com/rackslab/RFL/releases/tag/v1.0.0
