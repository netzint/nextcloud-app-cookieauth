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
        // Note: We list common cookie names that may be relevant for debugging
        $cookieNames = $this->getRelevantCookieNames();

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
     * Get relevant cookie names for debugging (without exposing all cookies)
     *
     * @return array<string> List of relevant cookie names that are present
     */
    private function getRelevantCookieNames(): array
    {
        $relevantCookies = [
            'nc_session_id',
            'nc_token',
            'nc_username',
            'oc_sessionPassphrase',
            '__Host-nc_sameSiteCookielax',
            '__Host-nc_sameSiteCookiestrict',
        ];

        // Get the configured auth cookie name
        $authCookieName = \OC::$server->getConfig()->getSystemValue(
            'nextcloud-app-cookieauth',
            []
        )['cookie_name'] ?? 'authToken';

        $relevantCookies[] = $authCookieName;

        // Check which relevant cookies are present
        $presentCookies = [];
        foreach ($relevantCookies as $cookieName) {
            if ($this->request->getCookie($cookieName) !== null) {
                $presentCookies[] = $cookieName;
            }
        }

        return $presentCookies;
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

    /**
     * @NoAdminRequired
     * @NoCSRFRequired
     * @PublicPage
     *
     * Check if auth token exists in database for current session
     */
    public function tokenCheck(): JSONResponse
    {
        $sessionId = $this->session->getId();
        $user = $this->userSession->getUser();

        $tokenInfo = [
            'session_id' => substr($sessionId, 0, 16) . '...',
            'has_token' => false,
            'token_user' => null,
            'token_name' => null,
        ];

        try {
            $tokenProvider = \OC::$server->get(\OC\Authentication\Token\IProvider::class);
            $token = $tokenProvider->getToken($sessionId);

            $tokenInfo['has_token'] = true;
            $tokenInfo['token_user'] = $token->getUID();
            $tokenInfo['token_name'] = $token->getName();
            $tokenInfo['token_type'] = $token->getType();
        } catch (\Exception $e) {
            $tokenInfo['error'] = $e->getMessage();
        }

        return new JSONResponse([
            'is_logged_in' => $this->userSession->isLoggedIn(),
            'current_user' => $user ? $user->getUID() : null,
            'token' => $tokenInfo,
        ]);
    }
}
