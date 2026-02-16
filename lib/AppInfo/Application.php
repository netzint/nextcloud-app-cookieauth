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
use Psr\Log\LoggerInterface;

class Application extends App implements IBootstrap
{
    public const APP_ID = 'cookieauth';

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

        // Register the middleware that handles auto-login
        $context->registerMiddleware(CookieAuthMiddleware::class);
    }

    public function boot(IBootContext $context): void
    {
        // Auto-login is handled by the middleware, not here
        // This prevents duplicate login attempts
    }
}
