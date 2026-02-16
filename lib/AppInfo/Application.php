<?php

declare(strict_types=1);

namespace OCA\CookieAuth\AppInfo;

use OCA\CookieAuth\Auth\CookieAuthBackend;
use OCA\CookieAuth\Helper\LoginChain;
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
        // Register the LoginChain (uses Nextcloud's internal login commands)
        $context->registerService(LoginChain::class, function ($c) {
            return new LoginChain(
                $c->get(\OC\Authentication\Login\PreLoginHookCommand::class),
                $c->get(\OC\Authentication\Login\CompleteLoginCommand::class),
                $c->get(\OC\Authentication\Login\CreateSessionTokenCommand::class),
                $c->get(\OC\Authentication\Login\ClearLostPasswordTokensCommand::class),
                $c->get(\OC\Authentication\Login\UpdateLastPasswordConfirmCommand::class),
                $c->get(\OC\Authentication\Login\FinishRememberedLoginCommand::class),
            );
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

            // Inject the login chain
            try {
                $backend->setLoginChain($c->get(LoginChain::class));
            } catch (\Exception $e) {
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

        // Skip logout to allow proper logout
        if (str_starts_with($pathInfo, '/logout')) {
            return;
        }

        // Try auto-login
        $authBackend = $serverContainer->get(CookieAuthBackend::class);
        $loginSuccess = $authBackend->tryAutoLogin($userSession);

        // If login was successful and we're on the login page, redirect to home
        if ($loginSuccess && str_starts_with($pathInfo, '/login')) {
            $redirectUrl = $request->getParam('redirect_url');
            if ($redirectUrl) {
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
