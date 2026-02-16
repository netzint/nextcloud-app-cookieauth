<?php

declare(strict_types=1);

namespace OCA\JwtCookieAuth\Controller;

use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\JSONResponse;
use OCP\IRequest;
use OCP\IUserSession;

class AuthController extends Controller
{
    public function __construct(
        string $appName,
        IRequest $request,
        private IUserSession $userSession,
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
}
