# Changelog

All notable changes to the Cookie Auth app will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2025-02-20

### Added
- **Admin Settings UI**: Configure all settings via Nextcloud Admin > Security
  - Form fields for all configuration options
  - "Test Connection" button to verify Keycloak connectivity
  - Real-time status display (configured/not configured)
  - Migration button to import settings from config.php
- **ConfigService**: New service layer for configuration management
  - Automatic fallback: Admin UI settings > config.php > defaults
  - Full backwards compatibility with existing config.php setups
- **App Icon**: New app icon for settings section

### Changed
- Configuration can now be managed via Admin UI (no more manual config.php editing required)
- Updated info.xml with website and repository URLs
- Bumped max Nextcloud version to 32

### Documentation
- Updated README and description to mention Admin Settings UI

## [1.4.0] - 2025-02-17

### Added
- External password API support for SMB/external storage authentication
- Support for both NC 32.0.1 and NC 32.0.6+ LoginData constructor signatures

### Changed
- Improved README documentation with badges and better structure
- Updated minimum Nextcloud version to 25 in documentation

### Security
- Fixed open redirect vulnerability in login redirect handling
- Removed direct `$_COOKIE` access in favor of IRequest interface
- Debug endpoints now properly sanitize output

### Fixed
- LoginData constructor compatibility across Nextcloud versions

## [1.3.0] - 2025-02-16

### Added
- **Debug endpoint**: New `/debug` endpoint with detailed session diagnostics
- CSRF token generation for iframe SSO scenarios
- DAV backend authentication flag for WebDAV/CalDAV compatibility
- UserLoggedInEvent dispatch for modern Nextcloud app compatibility
- Recommendations output in debug endpoint

### Changed
- Improved session handling for complete login (no more "50% login" issues)
- Session is now explicitly saved after login
- Better post-login hook triggering with proper parameters

### Fixed
- Session not persisting in iframe scenarios
- CSRF token missing after cookie-based login

### Documentation
- Added critical `session_cookie_samesite` configuration for iframe SSO
- Extended troubleshooting section for iframe-related issues
- Added debug endpoint documentation

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
- Status endpoint at `/apps/nextcloud-app-cookieauth/status`
