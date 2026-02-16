<?php

declare(strict_types=1);

namespace OCA\CookieAuth\Controller;

use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\JSONResponse;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUserSession;

class AuthController extends Controller
{
    public function __construct(
        string $appName,
        IRequest $request,
        private IUserSession $userSession,
        private ISession $session,
    ) {
        parent::__construct($appName, $request);
    }

    /**
     * @NoAdminRequired
     * @NoCSRFRequired
     * @PublicPage
     *
     * Check authentication status - useful for debugging
     */
    public function status(): JSONResponse
    {
        $isLoggedIn = $this->userSession->isLoggedIn();
        $user = $this->userSession->getUser();

        return new JSONResponse([
            'authenticated' => $isLoggedIn,
            'user' => $user ? [
                'uid' => $user->getUID(),
                'displayName' => $user->getDisplayName(),
                'email' => $user->getEMailAddress(),
            ] : null,
        ]);
    }

    /**
     * @NoAdminRequired
     * @NoCSRFRequired
     * @PublicPage
     *
     * Detailed debug information about session state
     */
    public function debug(): JSONResponse
    {
        $isLoggedIn = $this->userSession->isLoggedIn();
        $user = $this->userSession->getUser();

        // Session diagnostic info
        $sessionInfo = [
            'session_id' => session_id() ?: 'no-session',
            'has_loginname' => $this->session->exists('loginname'),
            'has_user_id' => $this->session->exists('user_id'),
            'has_requesttoken' => $this->session->exists('requesttoken'),
            'has_cookieauth_key' => $this->session->exists('nextcloud_app_cookieauth_authenticated'),
            'has_dav_auth' => $this->session->exists('AUTHENTICATED_TO_DAV_BACKEND'),
        ];

        // Cookie info (names only, not values for security)
        $cookieNames = array_keys($_COOKIE ?? []);

        // Check SameSite configuration
        $sameSiteConfig = \OC::$server->getConfig()->getSystemValue('session_cookie_samesite', 'Lax');

        return new JSONResponse([
            'authenticated' => $isLoggedIn,
            'user' => $user ? [
                'uid' => $user->getUID(),
                'displayName' => $user->getDisplayName(),
            ] : null,
            'session' => $sessionInfo,
            'cookies_present' => $cookieNames,
            'config' => [
                'session_cookie_samesite' => $sameSiteConfig,
            ],
            'recommendations' => $this->getRecommendations($isLoggedIn, $sessionInfo, $sameSiteConfig),
        ]);
    }

    /**
     * Generate recommendations based on current state
     */
    private function getRecommendations(bool $isLoggedIn, array $sessionInfo, string $sameSiteConfig): array
    {
        $recommendations = [];

        if (!$isLoggedIn && !$sessionInfo['has_cookieauth_key']) {
            $recommendations[] = 'JWT cookie may not be reaching the server. Check cookie domain and SameSite settings.';
        }

        if ($sameSiteConfig !== 'None') {
            $recommendations[] = "For iframe SSO, add 'session_cookie_samesite' => 'None' to config.php";
        }

        if ($isLoggedIn && !$sessionInfo['has_requesttoken']) {
            $recommendations[] = 'CSRF token missing - this may cause issues with POST requests.';
        }

        if (empty($recommendations)) {
            $recommendations[] = 'Session looks correctly configured.';
        }

        return $recommendations;
    }
}
