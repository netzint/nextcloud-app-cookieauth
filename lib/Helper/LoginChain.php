<?php

declare(strict_types=1);

namespace OCA\CookieAuth\Helper;

use OC\Authentication\Login\ClearLostPasswordTokensCommand;
use OC\Authentication\Login\CompleteLoginCommand;
use OC\Authentication\Login\CreateSessionTokenCommand;
use OC\Authentication\Login\FinishRememberedLoginCommand;
use OC\Authentication\Login\LoginData;
use OC\Authentication\Login\LoginResult;
use OC\Authentication\Login\PreLoginHookCommand;
use OC\Authentication\Login\UpdateLastPasswordConfirmCommand;

/**
 * Custom login chain that uses Nextcloud's internal login commands
 * to properly set up the session and authentication tokens.
 *
 * This chain supports two modes:
 * - Full login: Triggers all events including PostLoginEvent (may overwrite stored credentials)
 * - Passwordless login: Skips CompleteLoginCommand to preserve existing external storage credentials
 */
class LoginChain
{
    public function __construct(
        private PreLoginHookCommand $preLoginHookCommand,
        private CompleteLoginCommand $completeLoginCommand,
        private CreateSessionTokenCommand $createSessionTokenCommand,
        private ClearLostPasswordTokensCommand $clearLostPasswordTokensCommand,
        private UpdateLastPasswordConfirmCommand $updateLastPasswordConfirmCommand,
        private FinishRememberedLoginCommand $finishRememberedLoginCommand,
    ) {
    }

    /**
     * Process full login chain (triggers PostLoginEvent - may overwrite stored credentials)
     */
    public function process(LoginData $loginData): LoginResult
    {
        $chain = $this->preLoginHookCommand;
        $chain
            ->setNext($this->completeLoginCommand)
            ->setNext($this->createSessionTokenCommand)
            ->setNext($this->clearLostPasswordTokensCommand)
            ->setNext($this->updateLastPasswordConfirmCommand)
            ->setNext($this->finishRememberedLoginCommand);

        return $chain->process($loginData);
    }

    /**
     * Process passwordless login - skips CompleteLoginCommand to preserve stored credentials.
     * Use this for JWT/SSO logins where we don't have the user's password.
     */
    public function processPasswordless(LoginData $loginData): LoginResult
    {
        // Skip PreLoginHookCommand and CompleteLoginCommand to avoid triggering
        // PostLoginEvent which would overwrite stored external storage credentials.
        // Go directly to CreateSessionTokenCommand for DAV authentication.
        $chain = $this->createSessionTokenCommand;
        $chain
            ->setNext($this->clearLostPasswordTokensCommand)
            ->setNext($this->updateLastPasswordConfirmCommand)
            ->setNext($this->finishRememberedLoginCommand);

        return $chain->process($loginData);
    }
}
