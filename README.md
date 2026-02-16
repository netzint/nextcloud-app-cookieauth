# Cookie Auth for Nextcloud

A Nextcloud app that enables automatic Single-Sign-On (SSO) when Nextcloud is embedded in an iframe. It reads a JWT token from a configurable cookie, validates it against a public key (e.g., from Keycloak), and automatically logs in the matching Nextcloud user.

## Use Case

This app is perfect for scenarios where:
- Nextcloud is embedded in an iframe within a portal application
- The portal uses Keycloak or another OIDC provider for authentication
- The JWT token is already present as a cookie from the parent application
- You want seamless SSO without redirecting users through another login flow

## Requirements

- Nextcloud 25 or higher
- PHP 8.1 or higher
- A JWT token in a cookie (e.g., from Keycloak)
- Users must already exist in Nextcloud (matching by username or email)

## Installation

1. Clone/copy this app to your Nextcloud apps directory:

```bash
cd /var/www/nextcloud/apps
git clone https://github.com/netzint/nextcloud-app-cookieauth nextcloud-app-cookieauth
```

2. Enable the app:

```bash
sudo -u www-data php occ app:enable nextcloud-app-cookieauth
```

## Configuration

Add the following to your `config/config.php`:

### Option 1: Auto-fetch Public Key from Keycloak (Recommended)

The app can automatically fetch the public key from your Keycloak realm:

```php
'nextcloud-app-cookieauth' => [
    // Keycloak Realm URL - public key is fetched automatically
    'realm_url' => 'https://my.netzint.de/auth/realms/edulution',

    // Name of the cookie containing the JWT token
    'cookie_name' => 'authToken',

    // JWT claim to use for matching users
    'user_claim' => 'preferred_username',

    // Optional: If user not found by username, try matching by email
    'fallback_to_email' => true,
],
```

The public key is cached for 1 hour to minimize HTTP requests.

### Option 2: Manual Public Key Configuration

If you prefer to provide the public key manually:

```php
'nextcloud-app-cookieauth' => [
    // Name of the cookie containing the JWT token
    'cookie_name' => 'authToken',

    // Path to the public key file (PEM format)
    // OR the key itself as a string starting with "-----BEGIN"
    'public_key' => '/etc/nextcloud/keycloak-public-key.pem',

    // JWT signing algorithm (RS256, RS384, RS512) - default: RS256
    'algorithm' => 'RS256',

    // JWT claim to use for matching users
    'user_claim' => 'preferred_username',

    // Optional: Expected issuer (for additional validation)
    'issuer' => 'https://my.netzint.de/auth/realms/edulution',

    // Optional: If user not found by username, try matching by email
    'fallback_to_email' => true,
],
```

### Configuration Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `realm_url` | Yes* | - | Keycloak realm URL (auto-fetches public key) |
| `public_key` | Yes* | - | Path to PEM file or PEM string |
| `cookie_name` | Yes | - | Name of the cookie containing the JWT |
| `user_claim` | Yes | - | JWT claim for username (e.g., `preferred_username`) |
| `algorithm` | No | `RS256` | JWT algorithm (RS256, RS384, RS512) |
| `issuer` | No | realm_url | Expected JWT issuer |
| `fallback_to_email` | No | `false` | Try email lookup if username not found |

*Either `realm_url` OR `public_key` must be provided.

## How It Works

```
Portal (with Keycloak)          Nextcloud (iframe)
       │                               │
       │  1. User logs in              │
       │  2. Keycloak sets authToken   │
       │     cookie                    │
       │                               │
       │  3. Portal loads iframe       │
       │ ─────────────────────────────>│
       │     (cookie is sent)          │
       │                               │  4. App reads cookie
       │                               │  5. Validates JWT signature
       │                               │  6. Extracts username
       │                               │  7. Logs in Nextcloud user
       │                               │
       │<───────────────────────────── │  8. Returns authenticated page
```

## Cookie Requirements

For the cookie to be sent with iframe requests:

1. **Same-Site**: `SameSite=None; Secure` if Nextcloud is on a different subdomain
2. **Domain**: Cookie domain must include the Nextcloud domain
3. **HTTPS**: Both portal and Nextcloud must use HTTPS

Example cookie:
```
Set-Cookie: authToken=eyJhbGci...; Path=/; Domain=.netzint.de; Secure; HttpOnly; SameSite=None
```

## Iframe SSO Configuration (CRITICAL)

When embedding Nextcloud in an iframe, you **MUST** configure Nextcloud's session cookie to work cross-origin.

Add to your `config/config.php`:

```php
// Required for iframe SSO - allows session cookie to be sent in cross-origin iframe
'session_cookie_samesite' => 'None',
```

Without this setting, the session cookie won't be sent with iframe requests and the login will appear to work but fail on subsequent requests.

## User Matching

Users must exist in Nextcloud before auto-login. The app matches by:

1. **Primary**: The claim specified in `user_claim` (e.g., `preferred_username`)
2. **Fallback** (if enabled): The `email` claim

Provision users via:
- LDAP synchronization
- Nextcloud User Provisioning API
- Manual creation

## Debugging

Check logs:
```bash
tail -f /var/www/nextcloud/data/nextcloud.log | grep nextcloud-app-cookieauth
```

### Status endpoint
```
GET /apps/nextcloud-app-cookieauth/status
```

Response:
```json
{
  "authenticated": true,
  "user": {
    "uid": "dennis.boelling",
    "displayName": "Dennis Boelling",
    "email": "dennis.boelling@netzint.de"
  }
}
```

### Debug endpoint (detailed session info)
```
GET /apps/nextcloud-app-cookieauth/debug
```

Response:
```json
{
  "authenticated": true,
  "user": { "uid": "dennis.boelling", "displayName": "Dennis Boelling" },
  "session": {
    "session_id": "abc123...",
    "has_loginname": true,
    "has_user_id": true,
    "has_requesttoken": true,
    "has_cookieauth_key": true,
    "has_dav_auth": true
  },
  "cookies_present": ["nc_session_id", "authToken"],
  "config": {
    "session_cookie_samesite": "None"
  },
  "recommendations": ["Session looks correctly configured."]
}
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "User not found" | Check user exists in Nextcloud, verify `user_claim` |
| "Signature verification failed" | Check public key, verify algorithm |
| "Token expired" | Normal - user needs fresh token from portal |
| "Issuer mismatch" | Check `issuer` config matches JWT |
| Cookie not sent | Check `SameSite=None; Secure`, verify domain |
| "Failed to fetch realm info" | Check `realm_url` is accessible from server |
| Login works but CSRF errors | Add `'session_cookie_samesite' => 'None'` to config.php |
| Login partial (50%) | Session cookie not persisting - check `session_cookie_samesite` |
| User shown but operations fail | Use `/debug` endpoint to check session state |

## Security

- Always use HTTPS
- Validate the issuer
- Token expiration is enforced (`exp` and `nbf` claims)
- Public key is cached securely in Nextcloud database
- Session cleared on token validation failure

## License

AGPL-3.0-or-later

## Credits

Developed by Netzint GmbH for edulution.io
