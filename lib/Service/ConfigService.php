<?php

declare(strict_types=1);

namespace OCA\CookieAuth\Service;

use OCP\IConfig;

/**
 * Configuration service with fallback support for backwards compatibility.
 *
 * Priority: App values (admin UI) > System values (config.php) > Defaults
 */
class ConfigService
{
    public const APP_ID = 'nextcloud-app-cookieauth';

    // Setting keys
    public const KEY_REALM_URL = 'realm_url';
    public const KEY_COOKIE_NAME = 'cookie_name';
    public const KEY_USER_CLAIM = 'user_claim';
    public const KEY_PUBLIC_KEY = 'public_key';
    public const KEY_ALGORITHM = 'algorithm';
    public const KEY_ISSUER = 'issuer';
    public const KEY_FALLBACK_TO_EMAIL = 'fallback_to_email';
    public const KEY_PASSWORD_API_URL = 'password_api_url';

    // Cache keys (existing)
    public const CACHE_KEY_PUBLIC_KEY = 'cached_public_key';
    public const CACHE_KEY_PUBLIC_KEY_TIME = 'cached_public_key_time';

    // Default values
    private const DEFAULTS = [
        self::KEY_REALM_URL => '',
        self::KEY_COOKIE_NAME => 'authToken',
        self::KEY_USER_CLAIM => 'preferred_username',
        self::KEY_PUBLIC_KEY => '',
        self::KEY_ALGORITHM => 'RS256',
        self::KEY_ISSUER => '',
        self::KEY_FALLBACK_TO_EMAIL => false,
        self::KEY_PASSWORD_API_URL => '',
    ];

    public function __construct(
        private IConfig $config,
    ) {
    }

    /**
     * Get a configuration value with fallback to config.php
     * Priority: App value > System value (config.php) > Default
     */
    public function get(string $key): string|bool
    {
        // Check app value first (from admin UI)
        $appValue = $this->config->getAppValue(self::APP_ID, $key, '');

        if ($appValue !== '') {
            // Handle boolean conversion
            if ($key === self::KEY_FALLBACK_TO_EMAIL) {
                return $appValue === 'true' || $appValue === '1';
            }
            return $appValue;
        }

        // Fall back to system value (config.php)
        $systemConfig = $this->config->getSystemValue(self::APP_ID, []);

        if (is_array($systemConfig) && isset($systemConfig[$key])) {
            return $systemConfig[$key];
        }

        // Return default
        return self::DEFAULTS[$key] ?? '';
    }

    /**
     * Set a configuration value (stores in app config)
     */
    public function set(string $key, string|bool $value): void
    {
        if (is_bool($value)) {
            $value = $value ? 'true' : 'false';
        }
        $this->config->setAppValue(self::APP_ID, $key, $value);
    }

    /**
     * Delete a configuration value from app config
     */
    public function delete(string $key): void
    {
        $this->config->deleteAppValue(self::APP_ID, $key);
    }

    /**
     * Get all configuration as array (for template)
     */
    public function getAll(): array
    {
        return [
            self::KEY_REALM_URL => $this->get(self::KEY_REALM_URL),
            self::KEY_COOKIE_NAME => $this->get(self::KEY_COOKIE_NAME),
            self::KEY_USER_CLAIM => $this->get(self::KEY_USER_CLAIM),
            self::KEY_PUBLIC_KEY => $this->get(self::KEY_PUBLIC_KEY),
            self::KEY_ALGORITHM => $this->get(self::KEY_ALGORITHM),
            self::KEY_ISSUER => $this->get(self::KEY_ISSUER),
            self::KEY_FALLBACK_TO_EMAIL => $this->get(self::KEY_FALLBACK_TO_EMAIL),
            self::KEY_PASSWORD_API_URL => $this->get(self::KEY_PASSWORD_API_URL),
        ];
    }

    /**
     * Check if config is coming from config.php (legacy mode)
     */
    public function isLegacyMode(): bool
    {
        $systemConfig = $this->config->getSystemValue(self::APP_ID, null);
        return $systemConfig !== null && is_array($systemConfig) && !empty($systemConfig);
    }

    /**
     * Get the source of a config value ('app', 'system', or 'default')
     */
    public function getConfigSource(string $key): string
    {
        $appValue = $this->config->getAppValue(self::APP_ID, $key, '');
        if ($appValue !== '') {
            return 'app';
        }

        $systemConfig = $this->config->getSystemValue(self::APP_ID, []);
        if (is_array($systemConfig) && isset($systemConfig[$key])) {
            return 'system';
        }

        return 'default';
    }

    /**
     * Migrate all settings from config.php to app config
     */
    public function migrateFromSystemConfig(): bool
    {
        $systemConfig = $this->config->getSystemValue(self::APP_ID, null);

        if (!is_array($systemConfig) || empty($systemConfig)) {
            return false;
        }

        foreach (array_keys(self::DEFAULTS) as $key) {
            if (isset($systemConfig[$key])) {
                $this->set($key, $systemConfig[$key]);
            }
        }

        return true;
    }

    /**
     * Clear all app config values
     */
    public function clearAppConfig(): void
    {
        foreach (array_keys(self::DEFAULTS) as $key) {
            $this->config->deleteAppValue(self::APP_ID, $key);
        }
    }

    /**
     * Check if the configuration is valid
     */
    public function isConfigured(): bool
    {
        $hasRealmUrl = !empty($this->get(self::KEY_REALM_URL));
        $hasPublicKey = !empty($this->get(self::KEY_PUBLIC_KEY));
        $hasCookieName = !empty($this->get(self::KEY_COOKIE_NAME));
        $hasUserClaim = !empty($this->get(self::KEY_USER_CLAIM));

        return ($hasRealmUrl || $hasPublicKey) && $hasCookieName && $hasUserClaim;
    }

    /**
     * Get validation issues
     */
    public function getValidationIssues(): array
    {
        $issues = [];

        if (empty($this->get(self::KEY_COOKIE_NAME))) {
            $issues[] = 'Cookie name is not configured';
        }

        if (empty($this->get(self::KEY_USER_CLAIM))) {
            $issues[] = 'User claim is not configured';
        }

        $hasRealmUrl = !empty($this->get(self::KEY_REALM_URL));
        $hasPublicKey = !empty($this->get(self::KEY_PUBLIC_KEY));

        if (!$hasRealmUrl && !$hasPublicKey) {
            $issues[] = 'Neither Realm URL nor Public Key is configured';
        }

        return $issues;
    }

    /**
     * Get configuration mode ('keycloak', 'manual', or 'none')
     */
    public function getConfigMode(): string
    {
        $hasRealmUrl = !empty($this->get(self::KEY_REALM_URL));
        $hasPublicKey = !empty($this->get(self::KEY_PUBLIC_KEY));

        if ($hasRealmUrl) {
            return 'keycloak';
        }
        if ($hasPublicKey) {
            return 'manual';
        }
        return 'none';
    }
}
