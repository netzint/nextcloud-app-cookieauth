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

        // Try auto-login early, before Nextcloud redirects to login page
        $authBackend = $serverContainer->get(CookieAuthBackend::class);
        $loginSuccess = $authBackend->tryAutoLogin($userSession);

        // If login was successful and we're on the login page, redirect to home
        if ($loginSuccess) {
            $request = $serverContainer->get(IRequest::class);
            $pathInfo = $request->getPathInfo();

            // If on login page, redirect to the requested URL or home
            if (str_starts_with($pathInfo, '/login')) {
                $redirectUrl = $request->getParam('redirect_url');
                if ($redirectUrl) {
                    // Validate redirect URL to prevent open redirects
                    $redirectUrl = urldecode($redirectUrl);
                    if (!str_starts_with($redirectUrl, '/')) {
                        $redirectUrl = '/';
                    }
                } else {
                    $redirectUrl = '/';
                }

                header('Location: ' . $redirectUrl);
                exit();
            }
        }
    }
}
