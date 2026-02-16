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
}
