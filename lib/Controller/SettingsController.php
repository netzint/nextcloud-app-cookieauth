<?php

declare(strict_types=1);

namespace OCA\CookieAuth\Controller;

use OCA\CookieAuth\Service\ConfigService;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\AuthorizedAdminSetting;
use OCP\AppFramework\Http\JSONResponse;
use OCP\IRequest;

/**
 * Controller for admin settings API endpoints
 */
class SettingsController extends Controller
{
    public function __construct(
        string $appName,
        IRequest $request,
        private ConfigService $configService,
    ) {
        parent::__construct($appName, $request);
    }

    /**
     * Save all settings
     *
     * @AuthorizedAdminSetting(settings=OCA\CookieAuth\Settings\Admin)
     */
    #[AuthorizedAdminSetting(settings: \OCA\CookieAuth\Settings\Admin::class)]
    public function save(
        string $realm_url = '',
        string $cookie_name = '',
        string $user_claim = '',
        string $public_key = '',
        string $algorithm = 'RS256',
        string $issuer = '',
        bool $fallback_to_email = false,
        string $password_api_url = '',
    ): JSONResponse {
        try {
            // Validate required fields
            if (empty($cookie_name)) {
                return new JSONResponse([
                    'status' => 'error',
                    'message' => 'Cookie name is required',
                ], Http::STATUS_BAD_REQUEST);
            }

            if (empty($user_claim)) {
                return new JSONResponse([
                    'status' => 'error',
                    'message' => 'User claim is required',
                ], Http::STATUS_BAD_REQUEST);
            }

            // Must have either realm_url or public_key
            if (empty($realm_url) && empty($public_key)) {
                return new JSONResponse([
                    'status' => 'error',
                    'message' => 'Either Realm URL or Public Key must be provided',
                ], Http::STATUS_BAD_REQUEST);
            }

            // Validate algorithm
            $validAlgorithms = ['RS256', 'RS384', 'RS512'];
            if (!in_array($algorithm, $validAlgorithms, true)) {
                return new JSONResponse([
                    'status' => 'error',
                    'message' => 'Invalid algorithm. Must be RS256, RS384, or RS512',
                ], Http::STATUS_BAD_REQUEST);
            }

            // Validate URLs
            if (!empty($realm_url) && !filter_var($realm_url, FILTER_VALIDATE_URL)) {
                return new JSONResponse([
                    'status' => 'error',
                    'message' => 'Invalid Realm URL format',
                ], Http::STATUS_BAD_REQUEST);
            }

            if (!empty($password_api_url) && !filter_var($password_api_url, FILTER_VALIDATE_URL)) {
                return new JSONResponse([
                    'status' => 'error',
                    'message' => 'Invalid Password API URL format',
                ], Http::STATUS_BAD_REQUEST);
            }

            // Save all settings
            $this->configService->set(ConfigService::KEY_REALM_URL, $realm_url);
            $this->configService->set(ConfigService::KEY_COOKIE_NAME, $cookie_name);
            $this->configService->set(ConfigService::KEY_USER_CLAIM, $user_claim);
            $this->configService->set(ConfigService::KEY_PUBLIC_KEY, $public_key);
            $this->configService->set(ConfigService::KEY_ALGORITHM, $algorithm);
            $this->configService->set(ConfigService::KEY_ISSUER, $issuer);
            $this->configService->set(ConfigService::KEY_FALLBACK_TO_EMAIL, $fallback_to_email);
            $this->configService->set(ConfigService::KEY_PASSWORD_API_URL, $password_api_url);

            return new JSONResponse([
                'status' => 'success',
                'message' => 'Settings saved successfully',
            ]);
        } catch (\Exception $e) {
            return new JSONResponse([
                'status' => 'error',
                'message' => 'Failed to save settings: ' . $e->getMessage(),
            ], Http::STATUS_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Test connection to Keycloak realm
     *
     * @AuthorizedAdminSetting(settings=OCA\CookieAuth\Settings\Admin)
     */
    #[AuthorizedAdminSetting(settings: \OCA\CookieAuth\Settings\Admin::class)]
    public function testConnection(string $realm_url = ''): JSONResponse
    {
        if (empty($realm_url)) {
            // Try to get from saved config
            $realm_url = $this->configService->get(ConfigService::KEY_REALM_URL);
        }

        if (empty($realm_url)) {
            return new JSONResponse([
                'status' => 'error',
                'message' => 'No Realm URL provided',
            ], Http::STATUS_BAD_REQUEST);
        }

        if (!filter_var($realm_url, FILTER_VALIDATE_URL)) {
            return new JSONResponse([
                'status' => 'error',
                'message' => 'Invalid Realm URL format',
            ], Http::STATUS_BAD_REQUEST);
        }

        try {
            $realm_url = rtrim($realm_url, '/');

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

            $response = @file_get_contents($realm_url, false, $context);

            if ($response === false) {
                $error = error_get_last();
                return new JSONResponse([
                    'status' => 'error',
                    'message' => 'Failed to connect to Keycloak realm',
                    'details' => $error['message'] ?? 'Unknown error',
                ], Http::STATUS_BAD_GATEWAY);
            }

            $realmInfo = json_decode($response, true);

            if (!$realmInfo) {
                return new JSONResponse([
                    'status' => 'error',
                    'message' => 'Invalid response from Keycloak (not valid JSON)',
                ], Http::STATUS_BAD_GATEWAY);
            }

            if (!isset($realmInfo['public_key'])) {
                return new JSONResponse([
                    'status' => 'error',
                    'message' => 'Keycloak response does not contain public_key',
                    'details' => 'This may not be a valid Keycloak realm endpoint',
                ], Http::STATUS_BAD_GATEWAY);
            }

            // Success - return some useful info
            return new JSONResponse([
                'status' => 'success',
                'message' => 'Successfully connected to Keycloak realm',
                'realm' => $realmInfo['realm'] ?? 'unknown',
                'public_key_length' => strlen($realmInfo['public_key']),
                'token_service' => $realmInfo['token-service'] ?? null,
            ]);
        } catch (\Exception $e) {
            return new JSONResponse([
                'status' => 'error',
                'message' => 'Connection test failed: ' . $e->getMessage(),
            ], Http::STATUS_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Get current configuration status
     *
     * @AuthorizedAdminSetting(settings=OCA\CookieAuth\Settings\Admin)
     */
    #[AuthorizedAdminSetting(settings: \OCA\CookieAuth\Settings\Admin::class)]
    public function status(): JSONResponse
    {
        return new JSONResponse([
            'configured' => $this->configService->isConfigured(),
            'mode' => $this->configService->getConfigMode(),
            'issues' => $this->configService->getValidationIssues(),
            'isLegacyMode' => $this->configService->isLegacyMode(),
        ]);
    }

    /**
     * Migrate settings from config.php to app config
     *
     * @AuthorizedAdminSetting(settings=OCA\CookieAuth\Settings\Admin)
     */
    #[AuthorizedAdminSetting(settings: \OCA\CookieAuth\Settings\Admin::class)]
    public function migrate(): JSONResponse
    {
        try {
            $migrated = $this->configService->migrateFromSystemConfig();

            if ($migrated) {
                return new JSONResponse([
                    'status' => 'success',
                    'message' => 'Settings migrated from config.php successfully',
                ]);
            }

            return new JSONResponse([
                'status' => 'info',
                'message' => 'No settings found in config.php to migrate',
            ]);
        } catch (\Exception $e) {
            return new JSONResponse([
                'status' => 'error',
                'message' => 'Migration failed: ' . $e->getMessage(),
            ], Http::STATUS_INTERNAL_SERVER_ERROR);
        }
    }
}
