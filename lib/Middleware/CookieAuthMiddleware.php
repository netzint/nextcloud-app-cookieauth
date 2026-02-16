<?php

declare(strict_types=1);

namespace OCA\CookieAuth\Middleware;

use OCA\CookieAuth\Auth\CookieAuthBackend;
use OCP\AppFramework\Middleware;
use OCP\IRequest;
use OCP\IUserSession;

class CookieAuthMiddleware extends Middleware
{
    public function __construct(
        private IUserSession $userSession,
        private IRequest $request,
        private CookieAuthBackend $authBackend,
    ) {
    }

    /**
     * This method is called before the controller method is executed.
     * We use this to try auto-login before any request processing.
     */
    public function beforeController(mixed $controller, string $methodName): void
    {
        // Skip if already logged in
        if ($this->userSession->isLoggedIn()) {
            return;
        }

        // Skip for certain paths (login page, cron, etc.)
        $pathInfo = $this->request->getPathInfo();
        $skipPaths = ['/login', '/logout', '/cron.php', '/status.php', '/ocs/'];

        foreach ($skipPaths as $skipPath) {
            if (str_starts_with($pathInfo, $skipPath)) {
                return;
            }
        }

        // Try auto-login using the injected backend service
        $this->authBackend->tryAutoLogin($this->userSession);
    }
}
