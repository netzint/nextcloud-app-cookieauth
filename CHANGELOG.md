# Changelog

All notable changes to the Cookie Auth app will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2025-02-16

### Added
- **Auto-fetch Public Key**: New `realm_url` config option to automatically fetch public key from Keycloak
- Public key caching (1 hour TTL) to minimize HTTP requests
- Issuer is now automatically derived from `realm_url` if not explicitly set
- Algorithm defaults to RS256 if not specified

### Changed
- `public_key` is now optional if `realm_url` is provided
- Improved configuration validation with clearer error messages

## [1.1.0] - 2025-02-16

### Changed
- Refactored to use proper Dependency Injection via Service Container
- Middleware now receives `CookieAuthBackend` via constructor injection
- Removed duplicate authentication attempts (was in both `boot()` and middleware)
- Improved session validation with token expiration tracking

### Fixed
- Type-safety: `base64UrlDecode()` now properly returns `null` on failure
- Multi-email lookup now logs warning when multiple users share same email
- OpenSSL errors are now properly logged with error details
- Session race condition fixed by validating token expiration

### Security
- Added proper null-checks for all base64 decode operations
- Clear session data on token validation failure
- Better error handling prevents information leakage

## [1.0.0] - 2025-02-03

### Added
- Initial release
- JWT token validation from cookie
- Support for RS256, RS384, RS512 algorithms
- Auto-login for Nextcloud users
- Keycloak integration support
- Configurable user claim mapping
- Optional issuer validation
- Fallback to email lookup
- Debug endpoint at `/apps/nextcloud-app-cookieauth/status`
