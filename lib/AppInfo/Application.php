<?php

declare(strict_types=1);

namespace OCA\CookieAuth\AppInfo;

use OCA\CookieAuth\Auth\CookieAuthBackend;
use OCA\CookieAuth\Helper\LoginChain;
use OCA\CookieAuth\Middleware\CookieAuthMiddleware;
use OCA\CookieAuth\Service\ConfigService;
use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCP\IConfig;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUserManager;
use OCP\IUserSession;
use Psr\Log\LoggerInterface;

class Application extends App implements IBootstrap
{
    public const APP_ID = 'nextcloud-app-cookieauth';

    public function __construct(array $urlParams = [])
    {
        parent::__construct(self::APP_ID, $urlParams);
    }

    public function register(IRegistrationContext $context): void
    {
        // Register ConfigService for settings management
        $context->registerService(ConfigService::class, function ($c) {
            return new ConfigService(
                $c->get(IConfig::class),
            );
        });

        // Register the LoginChain (uses Nextcloud's internal login commands)
        // Wrapped in try-catch because internal classes may not exist in all NC versions
        $context->registerService(LoginChain::class, function ($c) {
            try {
                return new LoginChain(
                    $c->get(\OC\Authentication\Login\PreLoginHookCommand::class),
                    $c->get(\OC\Authentication\Login\CompleteLoginCommand::class),
                    $c->get(\OC\Authentication\Login\CreateSessionTokenCommand::class),
                    $c->get(\OC\Authentication\Login\ClearLostPasswordTokensCommand::class),
                    $c->get(\OC\Authentication\Login\UpdateLastPasswordConfirmCommand::class),
                    $c->get(\OC\Authentication\Login\FinishRememberedLoginCommand::class),
                );
            } catch (\Throwable $e) {
                // Classes might not exist in this Nextcloud version
                return null;
            }
        });

        // Register the CookieAuthBackend as a service
        $context->registerService(CookieAuthBackend::class, function ($c) {
            $backend = new CookieAuthBackend(
                $c->get(IUserManager::class),
                $c->get(IConfig::class),
                $c->get(LoggerInterface::class),
                $c->get(IRequest::class),
                $c->get(ISession::class),
            );

            // Inject the ConfigService
            $backend->setConfigService($c->get(ConfigService::class));

            // Inject the login chain (if available)
            try {
                $loginChain = $c->get(LoginChain::class);
                if ($loginChain !== null) {
                    $backend->setLoginChain($loginChain);
                }
            } catch (\Throwable $e) {
                // LoginChain might not be available in all Nextcloud versions
                // Fall back to manual login
            }

            return $backend;
        });

        // Register the middleware that handles auto-login for app routes
        $context->registerMiddleware(CookieAuthMiddleware::class);
    }

    public function boot(IBootContext $context): void
    {
        $serverContainer = $context->getServerContainer();

        // Skip for CLI requests
        if (php_sapi_name() === 'cli') {
            return;
        }

        // Get user session to check if already logged in
        $userSession = $serverContainer->get(IUserSession::class);

        // Skip if already logged in with a valid session
        if ($userSession->isLoggedIn()) {
            return;
        }

        $request = $serverContainer->get(IRequest::class);
        $pathInfo = $request->getPathInfo();
        $logger = $serverContainer->get(\Psr\Log\LoggerInterface::class);

        $logger->debug('CookieAuth: Boot - pathInfo: ' . $pathInfo, ['app' => 'nextcloud-app-cookieauth']);

        // Skip logout to allow proper logout
        if (str_starts_with($pathInfo, '/logout')) {
            return;
        }

        // Try auto-login
        $authBackend = $serverContainer->get(CookieAuthBackend::class);
        $loginSuccess = $authBackend->tryAutoLogin($userSession);

        $logger->debug('CookieAuth: Boot - loginSuccess: ' . ($loginSuccess ? 'true' : 'false') . ', pathInfo: ' . $pathInfo, ['app' => 'nextcloud-app-cookieauth']);

        // If login was successful and we're on the login page, redirect to home
        if ($loginSuccess && (str_starts_with($pathInfo, '/login') || $pathInfo === '')) {
            $redirectUrl = $request->getParam('redirect_url');
            $redirectUrl = $this->sanitizeRedirectUrl($redirectUrl);

            header('Location: ' . $redirectUrl);
            exit();
        }
    }

    /**
     * Sanitize redirect URL to prevent open redirect vulnerabilities
     *
     * Only allows relative paths starting with a single slash.
     * Rejects protocol-relative URLs (//), absolute URLs, and other schemes.
     */
    private function sanitizeRedirectUrl(?string $url): string
    {
        if ($url === null || $url === '') {
            return '/';
        }

        $url = urldecode($url);

        // Must start with exactly one slash (not // which is protocol-relative)
        if (!str_starts_with($url, '/') || str_starts_with($url, '//')) {
            return '/';
        }

        // Block any URL containing : before the first / (catches javascript:, data:, etc.)
        $colonPos = strpos($url, ':');
        $slashPos = strpos($url, '/', 1);
        if ($colonPos !== false && ($slashPos === false || $colonPos < $slashPos)) {
            return '/';
        }

        return $url;
    }
}
