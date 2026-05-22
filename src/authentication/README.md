# RFL: authentication package

User identity types, JWT token management, LDAP authentication, and OpenID
Connect (OIDC) client support.

## Installation

The core package installs only `RFL.core`. Optional backends are installed via
pip extras:

| Extra | Dependencies | Use |
|-------|----------------|-----|
| `jwt` | PyJWT | `rfl.authentication.jwt` |
| `ldap` | python-ldap | `rfl.authentication.ldap` |
| `oidc` | Authlib, Flask, requests | `rfl.authentication.oidc` |
| `all` | All of the above | Full authentication stack |

Examples:

```bash
pip install RFL.authentication          # user types and errors only
pip install "RFL.authentication[jwt]"   # JWT support
pip install "RFL.authentication[ldap]"  # LDAP support
pip install "RFL.authentication[oidc]"  # OIDC support
pip install "RFL.authentication[all]"   # all backends
```
