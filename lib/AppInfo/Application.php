<?php

declare(strict_types=1);

namespace OCA\CookieAuth\AppInfo;

use OCA\CookieAuth\Auth\CookieAuthBackend;
use OCA\CookieAuth\Middleware\CookieAuthMiddleware;
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
        // Register the CookieAuthBackend as a service
        $context->registerService(CookieAuthBackend::class, function ($c) {
            return new CookieAuthBackend(
                $c->get(IUserManager::class),
                $c->get(IConfig::class),
                $c->get(LoggerInterface::class),
                $c->get(IRequest::class),
                $c->get(ISession::class),
            );
        });

        // Register the middleware that handles auto-login for app routes
        $context->registerMiddleware(CookieAuthMiddleware::class);
    }

    public function boot(IBootContext $context): void
    {
        $serverContainer = $context->getServerContainer();

        // Get user session to check if already logged in
        $userSession = $serverContainer->get(IUserSession::class);

        // Skip if already logged in
        if ($userSession->isLoggedIn()) {
            return;
        }

        // Skip for CLI requests
        if (php_sapi_name() === 'cli') {
            return;
        }

        $request = $serverContainer->get(IRequest::class);

        // Skip AJAX requests - they should not trigger auto-login
        if ($request->getHeader('X-Requested-With') === 'XMLHttpRequest' ||
            $request->getHeader('OCS-APIREQUEST') === 'true') {
            return;
        }

        // Skip API and status requests
        $pathInfo = $request->getPathInfo();
        $skipPaths = ['/ocs/', '/remote.php/', '/status.php', '/cron.php', '/csrftoken'];
        foreach ($skipPaths as $skipPath) {
            if (str_contains($pathInfo, $skipPath)) {
                return;
            }
        }

        // Try auto-login early, before Nextcloud redirects to login page
        $authBackend = $serverContainer->get(CookieAuthBackend::class);
        $loginSuccess = $authBackend->tryAutoLogin($userSession);

        // If login was successful, redirect to refresh the page with new CSRF token
        if ($loginSuccess) {
            // Determine redirect URL
            if (str_starts_with($pathInfo, '/login')) {
                $redirectUrl = $request->getParam('redirect_url');
                if ($redirectUrl) {
                    $redirectUrl = urldecode($redirectUrl);
                    if (!str_starts_with($redirectUrl, '/')) {
                        $redirectUrl = '/';
                    }
                } else {
                    $redirectUrl = '/';
                }
            } else {
                // Redirect to current page to refresh CSRF token
                $redirectUrl = $request->getRequestUri();
            }

            // Add a marker to prevent infinite redirect loop
            if (!$request->getParam('_cookieauth_done')) {
                $separator = str_contains($redirectUrl, '?') ? '&' : '?';
                $redirectUrl .= $separator . '_cookieauth_done=1';

                header('Location: ' . $redirectUrl);
                exit();
            }
        }
    }
}
