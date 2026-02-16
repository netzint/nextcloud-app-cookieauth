<?php

declare(strict_types=1);

namespace OCA\JwtCookieAuth\AppInfo;

use OCA\JwtCookieAuth\Auth\JwtCookieAuthBackend;
use OCA\JwtCookieAuth\Middleware\JwtCookieAuthMiddleware;
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
    public const APP_ID = 'jwtcookieauth';

    public function __construct(array $urlParams = [])
    {
        parent::__construct(self::APP_ID, $urlParams);
    }

    public function register(IRegistrationContext $context): void
    {
        // Register the JwtCookieAuthBackend as a service
        $context->registerService(JwtCookieAuthBackend::class, function ($c) {
            return new JwtCookieAuthBackend(
                $c->get(IUserManager::class),
                $c->get(IConfig::class),
                $c->get(LoggerInterface::class),
                $c->get(IRequest::class),
                $c->get(ISession::class),
            );
        });

        // Register the middleware that handles auto-login
        $context->registerMiddleware(JwtCookieAuthMiddleware::class);
    }

    public function boot(IBootContext $context): void
    {
        // Auto-login is handled by the middleware, not here
        // This prevents duplicate login attempts
    }
}
