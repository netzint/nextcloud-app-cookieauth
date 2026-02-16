<?php

declare(strict_types=1);

namespace OCA\CookieAuth\Auth;

use OCA\CookieAuth\Helper\LoginChain;
use OCP\IConfig;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUserManager;
use OCP\IUserSession;
use Psr\Log\LoggerInterface;

class CookieAuthBackend
{
    private const SESSION_KEY = 'nextcloud_app_cookieauth_authenticated';
    private const SESSION_TOKEN_HASH = 'nextcloud_app_cookieauth_token_hash';
    private const SESSION_TOKEN_EXP = 'nextcloud_app_cookieauth_token_exp';
    private const CACHE_KEY_PUBLIC_KEY = 'nextcloud_app_cookieauth_cached_public_key';
    private const CACHE_KEY_PUBLIC_KEY_TIME = 'nextcloud_app_cookieauth_cached_public_key_time';
    private const CACHE_TTL = 3600; // Cache public key for 1 hour

    private ?LoginChain $loginChain = null;

    public function __construct(
        private IUserManager $userManager,
        private IConfig $config,
        private LoggerInterface $logger,
        private IRequest $request,
        private ISession $session,
    ) {
    }

    /**
     * Set the login chain (injected from Application)
     */
    public function setLoginChain(?LoginChain $loginChain): void
    {
        $this->loginChain = $loginChain;
    }

    /**
     * Try to auto-login the user based on JWT cookie
     */
    public function tryAutoLogin(IUserSession $userSession): bool
    {
        $appConfig = $this->getAppConfig();

        if (!$appConfig) {
            return false;
        }

        // Get JWT from cookie
        $token = $this->getTokenFromCookie($appConfig['cookie_name']);

        if (!$token) {
            $this->logger->debug('CookieAuth: No token found in cookie', ['app' => 'nextcloud-app-cookieauth']);
            return false;
        }

        // Check if we already processed this token in this session
        $tokenHash = hash('sha256', $token);
        $sessionTokenHash = $this->session->get(self::SESSION_TOKEN_HASH);
        $sessionTokenExp = $this->session->get(self::SESSION_TOKEN_EXP);

        // Validate session: check if token matches AND hasn't expired
        if ($this->session->exists(self::SESSION_KEY) &&
            $sessionTokenHash === $tokenHash &&
            $sessionTokenExp !== null &&
            $sessionTokenExp > time()) {
            $this->logger->debug('CookieAuth: Token already processed in this session', ['app' => 'nextcloud-app-cookieauth']);
            return true;
        }

        // Validate JWT
        $payload = $this->validateToken($token, $appConfig);

        if (!$payload) {
            // Clear any existing session data on validation failure
            $this->clearSessionData();
            return false;
        }

        // Extract username from payload
        $username = $this->extractUsername($payload, $appConfig);

        if (!$username) {
            $this->logger->warning('CookieAuth: Could not extract username from token', ['app' => 'nextcloud-app-cookieauth']);
            return false;
        }

        // Find user in Nextcloud
        $user = $this->userManager->get($username);

        // If not found by username, try by email
        if (!$user && isset($appConfig['fallback_to_email']) && $appConfig['fallback_to_email']) {
            $user = $this->findUserByEmail($payload);
        }

        if (!$user) {
            $this->logger->warning('CookieAuth: User not found in Nextcloud', [
                'app' => 'nextcloud-app-cookieauth',
                'username' => $username,
            ]);
            return false;
        }

        // Check if user is enabled
        if (!$user->isEnabled()) {
            $this->logger->warning('CookieAuth: User is disabled', [
                'app' => 'nextcloud-app-cookieauth',
                'username' => $username,
            ]);
            return false;
        }

        // Login the user using Nextcloud's internal login chain
        try {
            $uid = $user->getUID();

            // If there's an existing different user session, log out first
            // This prevents session conflicts
            if ($userSession instanceof \OC\User\Session) {
                $currentUser = $userSession->getUser();
                if ($currentUser !== null && $currentUser->getUID() !== $uid) {
                    $this->logger->debug('CookieAuth: Logging out existing user before new login', [
                        'app' => 'nextcloud-app-cookieauth',
                        'old_user' => $currentUser->getUID(),
                        'new_user' => $uid,
                    ]);
                    $userSession->logout();
                }
            }

            // Use the LoginChain if available (proper Nextcloud login flow)
            if ($this->loginChain !== null) {
                // Try to fetch real password from API (for proper SMB/external storage auth)
                $password = '';
                if (isset($appConfig['password_api_url']) && $appConfig['password_api_url'] !== '') {
                    $password = $this->fetchPasswordFromApi($uid, $token, $appConfig['password_api_url']);
                    if ($password) {
                        $this->logger->debug('CookieAuth: Retrieved password from API', [
                            'app' => 'nextcloud-app-cookieauth',
                            'username' => $username,
                        ]);
                    }
                }

                $loginData = new \OC\Authentication\Login\LoginData(
                    $this->request,
                    $uid,
                    $password, // Real password if available, empty otherwise
                    '/', // Redirect URL
                    '', // Timezone
                    '', // Timezone offset
                );

                // Pre-populate with the user
                $loginData->setUser($user);

                // Use full login chain for proper DAV authentication
                $result = $this->loginChain->process($loginData);

                if (!$result->isSuccess()) {
                    $this->logger->warning('CookieAuth: Login chain failed', [
                        'app' => 'nextcloud-app-cookieauth',
                        'username' => $username,
                    ]);
                    return false;
                }

                $this->logger->debug('CookieAuth: Login chain completed successfully', [
                    'app' => 'nextcloud-app-cookieauth',
                    'username' => $username,
                    'has_password' => $password !== '',
                ]);
            } else {
                // Fallback: Manual login (less reliable for DAV)
                $this->logger->debug('CookieAuth: Using fallback manual login', [
                    'app' => 'nextcloud-app-cookieauth',
                ]);

                $userSession->setUser($user);
                $this->session->set('loginname', $uid);
                $this->session->set('user_id', $uid);
                $this->session->set('last-login', time());

                // Try to create session token manually
                if ($userSession instanceof \OC\User\Session) {
                    try {
                        $userSession->createSessionToken(
                            $this->request,
                            $uid,
                            $uid,
                            '',
                            \OC\Authentication\Token\IToken::DO_NOT_REMEMBER,
                            \OC\Authentication\Token\IToken::TEMPORARY_TOKEN
                        );
                    } catch (\Exception $e) {
                        $this->logger->debug('CookieAuth: Session token creation failed: ' . $e->getMessage(), [
                            'app' => 'nextcloud-app-cookieauth',
                        ]);
                    }
                }

                $user->updateLastLoginTimestamp();
            }

            // Mark session as authenticated via JWT cookie
            $this->session->set(self::SESSION_KEY, true);
            $this->session->set(self::SESSION_TOKEN_HASH, $tokenHash);
            $this->session->set(self::SESSION_TOKEN_EXP, $payload['exp'] ?? (time() + 3600));

            $this->logger->info('CookieAuth: User logged in successfully', [
                'app' => 'nextcloud-app-cookieauth',
                'username' => $username,
            ]);
            return true;
        } catch (\Exception $e) {
            $this->logger->error('CookieAuth: Failed to login user', [
                'app' => 'nextcloud-app-cookieauth',
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);
            return false;
        }
    }

    /**
     * Find user by email from JWT payload
     */
    private function findUserByEmail(array $payload): ?\OCP\IUser
    {
        $email = $payload['email'] ?? null;
        if (!$email) {
            return null;
        }

        $users = $this->userManager->getByEmail($email);

        if (count($users) === 1) {
            return $users[0];
        }

        if (count($users) > 1) {
            $this->logger->warning('CookieAuth: Multiple users found with same email, cannot auto-login', [
                'app' => 'nextcloud-app-cookieauth',
                'email' => $email,
                'user_count' => count($users),
            ]);
        }

        return null;
    }

    /**
     * Clear JWT session data
     */
    private function clearSessionData(): void
    {
        $this->session->remove(self::SESSION_KEY);
        $this->session->remove(self::SESSION_TOKEN_HASH);
        $this->session->remove(self::SESSION_TOKEN_EXP);
    }

    /**
     * Get app configuration from config.php
     */
    private function getAppConfig(): ?array
    {
        $config = $this->config->getSystemValue('nextcloud-app-cookieauth', null);

        if (!$config || !is_array($config)) {
            $this->logger->debug('CookieAuth: No configuration found', ['app' => 'nextcloud-app-cookieauth']);
            return null;
        }

        // Check if realm_url is provided (auto-fetch mode)
        $hasRealmUrl = isset($config['realm_url']) && $config['realm_url'] !== '';
        $hasPublicKey = isset($config['public_key']) && $config['public_key'] !== '';

        // Must have either realm_url or public_key
        if (!$hasRealmUrl && !$hasPublicKey) {
            $this->logger->error('CookieAuth: Missing required config: realm_url or public_key', ['app' => 'nextcloud-app-cookieauth']);
            return null;
        }

        // Validate other required config
        $required = ['cookie_name', 'user_claim'];
        foreach ($required as $key) {
            if (!isset($config[$key]) || $config[$key] === '') {
                $this->logger->error("CookieAuth: Missing required config: $key", ['app' => 'nextcloud-app-cookieauth']);
                return null;
            }
        }

        // Set default algorithm if not provided
        if (!isset($config['algorithm']) || $config['algorithm'] === '') {
            $config['algorithm'] = 'RS256';
        }

        // If realm_url is provided, derive issuer from it if not set
        if ($hasRealmUrl && (!isset($config['issuer']) || $config['issuer'] === '')) {
            $config['issuer'] = $config['realm_url'];
        }

        return $config;
    }

    /**
     * Extract JWT from cookie
     */
    private function getTokenFromCookie(string $cookieName): ?string
    {
        $cookie = $this->request->getCookie($cookieName);

        if (!$cookie || $cookie === '') {
            return null;
        }

        return $cookie;
    }

    /**
     * Validate JWT token and return payload
     */
    private function validateToken(string $token, array $config): ?array
    {
        try {
            // Split token into parts
            $parts = explode('.', $token);
            if (count($parts) !== 3) {
                $this->logger->warning('CookieAuth: Invalid token format', ['app' => 'nextcloud-app-cookieauth']);
                return null;
            }

            [$headerB64, $payloadB64, $signatureB64] = $parts;

            // Decode header
            $headerJson = $this->base64UrlDecode($headerB64);
            if ($headerJson === null) {
                $this->logger->warning('CookieAuth: Failed to decode token header', ['app' => 'nextcloud-app-cookieauth']);
                return null;
            }

            $header = json_decode($headerJson, true);
            if (!$header || !isset($header['alg'])) {
                $this->logger->warning('CookieAuth: Invalid token header', ['app' => 'nextcloud-app-cookieauth']);
                return null;
            }

            // Check algorithm
            $expectedAlg = $config['algorithm'];
            if ($header['alg'] !== $expectedAlg) {
                $this->logger->warning('CookieAuth: Algorithm mismatch', [
                    'app' => 'nextcloud-app-cookieauth',
                    'expected' => $expectedAlg,
                    'got' => $header['alg'],
                ]);
                return null;
            }

            // Decode payload
            $payloadJson = $this->base64UrlDecode($payloadB64);
            if ($payloadJson === null) {
                $this->logger->warning('CookieAuth: Failed to decode token payload', ['app' => 'nextcloud-app-cookieauth']);
                return null;
            }

            $payload = json_decode($payloadJson, true);
            if (!$payload) {
                $this->logger->warning('CookieAuth: Invalid token payload', ['app' => 'nextcloud-app-cookieauth']);
                return null;
            }

            // Check expiration
            if (isset($payload['exp']) && $payload['exp'] < time()) {
                $this->logger->warning('CookieAuth: Token expired', ['app' => 'nextcloud-app-cookieauth']);
                return null;
            }

            // Check not before
            if (isset($payload['nbf']) && $payload['nbf'] > time()) {
                $this->logger->warning('CookieAuth: Token not yet valid', ['app' => 'nextcloud-app-cookieauth']);
                return null;
            }

            // Check issuer if configured
            if (isset($config['issuer']) && $config['issuer'] !== '') {
                if (!isset($payload['iss']) || $payload['iss'] !== $config['issuer']) {
                    $this->logger->warning('CookieAuth: Issuer mismatch', [
                        'app' => 'nextcloud-app-cookieauth',
                        'expected' => $config['issuer'],
                        'got' => $payload['iss'] ?? 'not set',
                    ]);
                    return null;
                }
            }

            // Verify signature
            if (!$this->verifySignature($headerB64, $payloadB64, $signatureB64, $config)) {
                $this->logger->warning('CookieAuth: Signature verification failed', ['app' => 'nextcloud-app-cookieauth']);
                return null;
            }

            return $payload;
        } catch (\Exception $e) {
            $this->logger->error('CookieAuth: Token validation error', [
                'app' => 'nextcloud-app-cookieauth',
                'error' => $e->getMessage(),
            ]);
            return null;
        }
    }

    /**
     * Get the public key - either from config or fetched from Keycloak realm
     */
    private function getPublicKey(array $config): ?string
    {
        // If public_key is directly provided, use it
        if (isset($config['public_key']) && $config['public_key'] !== '') {
            $publicKeyPath = $config['public_key'];

            // Key is provided directly as PEM string
            if (str_starts_with($publicKeyPath, '-----BEGIN')) {
                return $publicKeyPath;
            }

            // Key is a file path
            if (file_exists($publicKeyPath)) {
                $publicKey = file_get_contents($publicKeyPath);
                if ($publicKey === false) {
                    $this->logger->error('CookieAuth: Could not read public key file', [
                        'app' => 'nextcloud-app-cookieauth',
                        'path' => $publicKeyPath,
                    ]);
                    return null;
                }
                return $publicKey;
            }

            $this->logger->error('CookieAuth: Public key file not found', [
                'app' => 'nextcloud-app-cookieauth',
                'path' => $publicKeyPath,
            ]);
            return null;
        }

        // Fetch from realm_url
        if (isset($config['realm_url']) && $config['realm_url'] !== '') {
            return $this->fetchPublicKeyFromRealm($config['realm_url']);
        }

        return null;
    }

    /**
     * Fetch public key from Keycloak realm URL
     * Uses caching to avoid HTTP requests on every authentication
     */
    private function fetchPublicKeyFromRealm(string $realmUrl): ?string
    {
        // Check cache first
        $cachedKey = $this->config->getAppValue('nextcloud-app-cookieauth', self::CACHE_KEY_PUBLIC_KEY, '');
        $cacheTime = (int) $this->config->getAppValue('nextcloud-app-cookieauth', self::CACHE_KEY_PUBLIC_KEY_TIME, '0');

        if ($cachedKey !== '' && $cacheTime > 0 && (time() - $cacheTime) < self::CACHE_TTL) {
            $this->logger->debug('CookieAuth: Using cached public key', ['app' => 'nextcloud-app-cookieauth']);
            return $cachedKey;
        }

        // Fetch from Keycloak
        $this->logger->info('CookieAuth: Fetching public key from realm', [
            'app' => 'nextcloud-app-cookieauth',
            'realm_url' => $realmUrl,
        ]);

        $realmUrl = rtrim($realmUrl, '/');

        // Try to fetch realm info
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'timeout' => 10,
                'header' => 'Accept: application/json',
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ]);

        $response = @file_get_contents($realmUrl, false, $context);

        if ($response === false) {
            $this->logger->error('CookieAuth: Failed to fetch realm info', [
                'app' => 'nextcloud-app-cookieauth',
                'realm_url' => $realmUrl,
            ]);
            return null;
        }

        $realmInfo = json_decode($response, true);

        if (!$realmInfo || !isset($realmInfo['public_key'])) {
            $this->logger->error('CookieAuth: Invalid realm response or missing public_key', [
                'app' => 'nextcloud-app-cookieauth',
                'realm_url' => $realmUrl,
            ]);
            return null;
        }

        // Convert to PEM format
        $publicKey = "-----BEGIN PUBLIC KEY-----\n" .
            chunk_split($realmInfo['public_key'], 64, "\n") .
            "-----END PUBLIC KEY-----";

        // Cache the key
        $this->config->setAppValue('nextcloud-app-cookieauth', self::CACHE_KEY_PUBLIC_KEY, $publicKey);
        $this->config->setAppValue('nextcloud-app-cookieauth', self::CACHE_KEY_PUBLIC_KEY_TIME, (string) time());

        $this->logger->info('CookieAuth: Successfully fetched and cached public key', ['app' => 'nextcloud-app-cookieauth']);

        return $publicKey;
    }

    /**
     * Verify JWT signature
     */
    private function verifySignature(string $headerB64, string $payloadB64, string $signatureB64, array $config): bool
    {
        $data = "$headerB64.$payloadB64";
        $signature = $this->base64UrlDecode($signatureB64);

        if ($signature === null) {
            $this->logger->error('CookieAuth: Failed to decode signature', ['app' => 'nextcloud-app-cookieauth']);
            return false;
        }

        // Get public key (from config or fetched from realm)
        $publicKey = $this->getPublicKey($config);

        if (!$publicKey) {
            $this->logger->error('CookieAuth: Could not get public key', ['app' => 'nextcloud-app-cookieauth']);
            return false;
        }

        $algorithm = $config['algorithm'];

        // Map algorithm to OpenSSL constant
        $algMap = [
            'RS256' => OPENSSL_ALGO_SHA256,
            'RS384' => OPENSSL_ALGO_SHA384,
            'RS512' => OPENSSL_ALGO_SHA512,
        ];

        if (!isset($algMap[$algorithm])) {
            $this->logger->error('CookieAuth: Unsupported algorithm', [
                'app' => 'nextcloud-app-cookieauth',
                'algorithm' => $algorithm,
            ]);
            return false;
        }

        $key = openssl_pkey_get_public($publicKey);
        if (!$key) {
            $this->logger->error('CookieAuth: Invalid public key format', ['app' => 'nextcloud-app-cookieauth']);
            return false;
        }

        $result = openssl_verify($data, $signature, $key, $algMap[$algorithm]);

        if ($result === -1) {
            $this->logger->error('CookieAuth: OpenSSL verification error', [
                'app' => 'nextcloud-app-cookieauth',
                'error' => openssl_error_string(),
            ]);
            return false;
        }

        return $result === 1;
    }

    /**
     * Extract username from JWT payload based on config
     */
    private function extractUsername(array $payload, array $config): ?string
    {
        $claim = $config['user_claim'];

        // Support nested claims with dot notation (e.g., "user.name")
        $parts = explode('.', $claim);
        $value = $payload;

        foreach ($parts as $part) {
            if (!is_array($value) || !isset($value[$part])) {
                return null;
            }
            $value = $value[$part];
        }

        if (!is_string($value)) {
            return null;
        }

        return $value;
    }

    /**
     * Base64 URL decode with proper error handling
     *
     * @param string $data Base64 URL encoded string
     * @return string|null Decoded string or null on failure
     */
    private function base64UrlDecode(string $data): ?string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode(strtr($data, '-_', '+/'), true);

        if ($decoded === false) {
            return null;
        }

        return $decoded;
    }

    /**
     * Fetch user's password from external API (e.g., Edulution)
     *
     * @param string $username The username to fetch password for
     * @param string $jwtToken The JWT token to use for authentication
     * @param string $apiUrl The base API URL
     * @return string The password, or empty string on failure
     */
    private function fetchPasswordFromApi(string $username, string $jwtToken, string $apiUrl): string
    {
        try {
            $apiUrl = rtrim($apiUrl, '/');
            $url = "{$apiUrl}/users/{$username}/key";

            $this->logger->debug('CookieAuth: Fetching password from API', [
                'app' => 'nextcloud-app-cookieauth',
                'url' => $url,
            ]);

            $context = stream_context_create([
                'http' => [
                    'method' => 'GET',
                    'timeout' => 10,
                    'header' => [
                        "Authorization: Bearer {$jwtToken}",
                        'Accept: application/json',
                    ],
                ],
                'ssl' => [
                    'verify_peer' => true,
                    'verify_peer_name' => true,
                ],
            ]);

            $response = @file_get_contents($url, false, $context);

            if ($response === false) {
                $this->logger->warning('CookieAuth: Failed to fetch password from API', [
                    'app' => 'nextcloud-app-cookieauth',
                    'url' => $url,
                ]);
                return '';
            }

            // Response is base64 encoded password (possibly with quotes)
            $passwordBase64 = trim($response, " \t\n\r\0\x0B\"");
            $password = base64_decode($passwordBase64, true);

            if ($password === false) {
                $this->logger->warning('CookieAuth: Failed to decode password from API', [
                    'app' => 'nextcloud-app-cookieauth',
                ]);
                return '';
            }

            $this->logger->info('CookieAuth: Successfully retrieved password from API', [
                'app' => 'nextcloud-app-cookieauth',
                'username' => $username,
            ]);

            return $password;
        } catch (\Exception $e) {
            $this->logger->error('CookieAuth: Error fetching password from API', [
                'app' => 'nextcloud-app-cookieauth',
                'error' => $e->getMessage(),
            ]);
            return '';
        }
    }
}
