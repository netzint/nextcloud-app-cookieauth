# Cookie Auth for Nextcloud

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Nextcloud](https://img.shields.io/badge/Nextcloud-25%2B-blue)](https://nextcloud.com)
[![PHP](https://img.shields.io/badge/PHP-8.1%2B-purple)](https://php.net)

A Nextcloud app that enables automatic Single-Sign-On (SSO) when Nextcloud is embedded in an iframe. It reads a JWT token from a configurable cookie, validates it against a public key (e.g., from Keycloak), and automatically logs in the matching Nextcloud user.

## Features

- **JWT Authentication**: Validates JWT tokens from cookies using RS256/RS384/RS512 algorithms
- **Keycloak Integration**: Auto-fetches public keys from Keycloak realms
- **Flexible User Matching**: Match users by username claim or email fallback
- **Session Caching**: Prevents redundant token validation
- **External Password API**: Optional integration for SMB/external storage authentication
- **Debug Endpoints**: Built-in diagnostics for troubleshooting

## Use Case

This app is designed for scenarios where:

- Nextcloud is embedded in an iframe within a portal application
- The portal uses Keycloak or another OIDC provider for authentication
- The JWT token is already present as a cookie from the parent application
- You want seamless SSO without redirecting users through another login flow

## Requirements

| Requirement | Version |
|-------------|---------|
| Nextcloud | 25 or higher |
| PHP | 8.1 or higher |

Additional requirements:
- A JWT token in a cookie (e.g., from Keycloak)
- Users must already exist in Nextcloud (matching by username or email)
- HTTPS for both portal and Nextcloud

## Installation

### From Git

```bash
cd /var/www/nextcloud/apps
git clone https://github.com/netzint/nextcloud-app-cookieauth
```

### Enable the App

```bash
sudo -u www-data php occ app:enable nextcloud-app-cookieauth
```

## Configuration

Add the following to your `config/config.php`:

### Required: Session Cookie Configuration

For iframe SSO to work, you **must** configure Nextcloud's session cookie:

```php
// Required for iframe SSO - allows session cookie to be sent cross-origin
'session_cookie_samesite' => 'None',
```

### Option 1: Auto-fetch Public Key from Keycloak (Recommended)

```php
'nextcloud-app-cookieauth' => [
    // Keycloak Realm URL - public key is fetched automatically
    'realm_url' => 'https://your-edulution-domain.com/auth/realms/edulution',

    // Name of the cookie containing the JWT token
    'cookie_name' => 'authToken',

    // JWT claim to use for matching users
    'user_claim' => 'preferred_username',

    // Optional: If user not found by username, try matching by email
    'fallback_to_email' => true,

    // Optional: API to fetch user's password for SMB/external storage
    'password_api_url' => 'https://api.example.com',
],
```

The public key is cached for 1 hour to minimize HTTP requests.

### Option 2: Manual Public Key Configuration

```php
'nextcloud-app-cookieauth' => [
    // Name of the cookie containing the JWT token
    'cookie_name' => 'authToken',

    // Path to the public key file (PEM format)
    // OR the key itself as a string starting with "-----BEGIN"
    'public_key' => '/etc/nextcloud/keycloak-public-key.pem',

    // JWT signing algorithm (RS256, RS384, RS512)
    'algorithm' => 'RS256',

    // JWT claim to use for matching users
    'user_claim' => 'preferred_username',

    // Optional: Expected issuer (for additional validation)
    'issuer' => 'https://your-edulution-domain.com/auth/realms/edulution',

    // Optional: If user not found by username, try matching by email
    'fallback_to_email' => true,
],
```

### Configuration Reference

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `realm_url` | Yes* | - | Keycloak realm URL (auto-fetches public key) |
| `public_key` | Yes* | - | Path to PEM file or PEM string |
| `cookie_name` | Yes | - | Name of the cookie containing the JWT |
| `user_claim` | Yes | - | JWT claim for username (e.g., `preferred_username`) |
| `algorithm` | No | `RS256` | JWT algorithm (RS256, RS384, RS512) |
| `issuer` | No | `realm_url` | Expected JWT issuer for validation |
| `fallback_to_email` | No | `false` | Try email lookup if username not found |
| `password_api_url` | No | - | API URL to fetch user passwords for external storage |

*Either `realm_url` OR `public_key` must be provided.

## How It Works

```
Portal (with Keycloak)              Nextcloud (iframe)
       │                                   │
       │  1. User logs in to portal        │
       │  2. Keycloak issues JWT token     │
       │     and sets cookie               │
       │                                   │
       │  3. Portal loads Nextcloud        │
       │     in iframe                     │
       │ ─────────────────────────────────>│
       │     (cookie is sent)              │
       │                                   │  4. App reads JWT from cookie
       │                                   │  5. Validates JWT signature
       │                                   │  6. Extracts username from claims
       │                                   │  7. Logs in Nextcloud user
       │                                   │
       │<───────────────────────────────── │  8. Returns authenticated page
```

## Cookie Requirements

For the cookie to be sent with iframe requests:

1. **SameSite**: Must be `SameSite=None; Secure` for cross-origin iframes
2. **Domain**: Cookie domain must include the Nextcloud domain
3. **HTTPS**: Both portal and Nextcloud must use HTTPS

Example cookie header:
```
Set-Cookie: authToken=eyJhbGci...; Path=/; Domain=.example.com; Secure; HttpOnly; SameSite=None
```

## User Provisioning

Users must exist in Nextcloud before auto-login can work. The app matches users by:

1. **Primary**: The claim specified in `user_claim` (e.g., `preferred_username`)
2. **Fallback** (if enabled): The `email` claim

Provision users via:
- LDAP synchronization
- Nextcloud User Provisioning API
- Manual creation
- External user backends

## Debug Endpoints

### Status Check

```
GET /apps/nextcloud-app-cookieauth/status
```

Returns basic authentication status:

```json
{
  "authenticated": true,
  "user": {
    "uid": "john.doe",
    "displayName": "John Doe",
    "email": "john.doe@example.com"
  }
}
```

### Detailed Debug Info

```
GET /apps/nextcloud-app-cookieauth/debug
```

Returns detailed session diagnostics including recommendations.

### Token Check

```
GET /apps/nextcloud-app-cookieauth/tokenCheck
```

Checks if a valid session token exists in the database.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "User not found" | Verify user exists in Nextcloud; check `user_claim` config |
| "Signature verification failed" | Check public key; verify algorithm matches |
| "Token expired" | User needs a fresh token from the portal |
| "Issuer mismatch" | Check `issuer` config matches JWT issuer claim |
| Cookie not sent | Verify `SameSite=None; Secure`; check cookie domain |
| "Failed to fetch realm info" | Verify `realm_url` is accessible from server |
| Login works but CSRF errors | Add `'session_cookie_samesite' => 'None'` to config.php |
| Login appears to work but fails | Session cookie not persisting; check `session_cookie_samesite` |
| User shown but operations fail | Use `/debug` endpoint to diagnose session state |

### Checking Logs

```bash
tail -f /var/www/nextcloud/data/nextcloud.log | grep cookieauth
```

## Security Considerations

- **HTTPS Required**: Always use HTTPS for both the portal and Nextcloud
- **Issuer Validation**: Configure the `issuer` option to validate token source
- **Token Expiration**: The app enforces `exp` and `nbf` claims
- **Key Caching**: Public keys are cached securely in Nextcloud's database
- **Session Security**: Session data is cleared on token validation failure
- **Algorithm Validation**: Only configured algorithms are accepted (prevents algorithm confusion attacks)

## Development

### Running Tests

```bash
composer install
composer test
```

### Test Coverage

```bash
composer test:coverage
```

## License

This project is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).

See [LICENSE](LICENSE) for the full license text.

## Credits

Developed by [Netzint GmbH](https://netzint.de)

## Support

- **Issues**: [GitHub Issues](https://github.com/netzint/nextcloud-app-cookieauth/issues)
- **Documentation**: This README
