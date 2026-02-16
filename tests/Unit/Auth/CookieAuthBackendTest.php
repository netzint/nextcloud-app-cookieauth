<?php

declare(strict_types=1);

namespace OCA\CookieAuth\Tests\Unit\Auth;

use OCA\CookieAuth\Auth\CookieAuthBackend;
use OCP\IConfig;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUser;
use OCP\IUserManager;
use OCP\IUserSession;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class CookieAuthBackendTest extends TestCase
{
    private CookieAuthBackend $backend;
    private IUserManager&MockObject $userManager;
    private IConfig&MockObject $config;
    private LoggerInterface&MockObject $logger;
    private IRequest&MockObject $request;
    private ISession&MockObject $session;

    private string $testPrivateKey = '';
    private string $testPublicKey = '';

    protected function setUp(): void
    {
        parent::setUp();

        $this->userManager = $this->createMock(IUserManager::class);
        $this->config = $this->createMock(IConfig::class);
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->request = $this->createMock(IRequest::class);
        $this->session = $this->createMock(ISession::class);

        $this->backend = new CookieAuthBackend(
            $this->userManager,
            $this->config,
            $this->logger,
            $this->request,
            $this->session
        );

        // Generate test RSA key pair
        $this->generateTestKeyPair();
    }

    private function generateTestKeyPair(): void
    {
        $config = [
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $this->testPrivateKey);

        $details = openssl_pkey_get_details($res);
        $this->testPublicKey = $details['key'];
    }

    private function createValidJwt(array $payload, string $algorithm = 'RS256'): string
    {
        $header = [
            'alg' => $algorithm,
            'typ' => 'JWT',
        ];

        $headerB64 = $this->base64UrlEncode(json_encode($header));
        $payloadB64 = $this->base64UrlEncode(json_encode($payload));

        $data = "$headerB64.$payloadB64";

        $algMap = [
            'RS256' => OPENSSL_ALGO_SHA256,
            'RS384' => OPENSSL_ALGO_SHA384,
            'RS512' => OPENSSL_ALGO_SHA512,
        ];

        openssl_sign($data, $signature, $this->testPrivateKey, $algMap[$algorithm]);
        $signatureB64 = $this->base64UrlEncode($signature);

        return "$headerB64.$payloadB64.$signatureB64";
    }

    private function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function getDefaultConfig(): array
    {
        return [
            'cookie_name' => 'authToken',
            'public_key' => $this->testPublicKey,
            'algorithm' => 'RS256',
            'user_claim' => 'preferred_username',
            'issuer' => 'https://test.example.com/auth',
        ];
    }

    public function testTryAutoLogin_NoConfig_ReturnsFalse(): void
    {
        $this->config->method('getSystemValue')
            ->with('nextcloud-app-cookieauth', null)
            ->willReturn(null);

        $userSession = $this->createMock(IUserSession::class);

        $result = $this->backend->tryAutoLogin($userSession);

        $this->assertFalse($result);
    }

    public function testTryAutoLogin_NoCookie_ReturnsFalse(): void
    {
        $this->config->method('getSystemValue')
            ->with('nextcloud-app-cookieauth', null)
            ->willReturn($this->getDefaultConfig());

        $this->request->method('getCookie')
            ->with('authToken')
            ->willReturn(null);

        $userSession = $this->createMock(IUserSession::class);

        $result = $this->backend->tryAutoLogin($userSession);

        $this->assertFalse($result);
    }

    public function testTryAutoLogin_ValidToken_LogsInUser(): void
    {
        $config = $this->getDefaultConfig();

        $this->config->method('getSystemValue')
            ->with('nextcloud-app-cookieauth', null)
            ->willReturn($config);

        $payload = [
            'preferred_username' => 'testuser',
            'email' => 'test@example.com',
            'exp' => time() + 3600,
            'iss' => 'https://test.example.com/auth',
        ];

        $token = $this->createValidJwt($payload);

        $this->request->method('getCookie')
            ->with('authToken')
            ->willReturn($token);

        $this->session->method('exists')->willReturn(false);
        $this->session->method('get')->willReturn(null);

        $user = $this->createMock(IUser::class);
        $user->method('isEnabled')->willReturn(true);

        $this->userManager->method('get')
            ->with('testuser')
            ->willReturn($user);

        $userSession = $this->createMock(IUserSession::class);
        $userSession->expects($this->once())
            ->method('setUser')
            ->with($user)
            ->willReturn(true);

        $result = $this->backend->tryAutoLogin($userSession);

        $this->assertTrue($result);
    }

    public function testTryAutoLogin_ExpiredToken_ReturnsFalse(): void
    {
        $config = $this->getDefaultConfig();

        $this->config->method('getSystemValue')
            ->with('nextcloud-app-cookieauth', null)
            ->willReturn($config);

        $payload = [
            'preferred_username' => 'testuser',
            'exp' => time() - 3600, // Expired 1 hour ago
            'iss' => 'https://test.example.com/auth',
        ];

        $token = $this->createValidJwt($payload);

        $this->request->method('getCookie')
            ->with('authToken')
            ->willReturn($token);

        $this->session->method('exists')->willReturn(false);
        $this->session->method('get')->willReturn(null);

        $userSession = $this->createMock(IUserSession::class);

        $result = $this->backend->tryAutoLogin($userSession);

        $this->assertFalse($result);
    }

    public function testTryAutoLogin_WrongIssuer_ReturnsFalse(): void
    {
        $config = $this->getDefaultConfig();

        $this->config->method('getSystemValue')
            ->with('nextcloud-app-cookieauth', null)
            ->willReturn($config);

        $payload = [
            'preferred_username' => 'testuser',
            'exp' => time() + 3600,
            'iss' => 'https://wrong-issuer.com/auth', // Wrong issuer
        ];

        $token = $this->createValidJwt($payload);

        $this->request->method('getCookie')
            ->with('authToken')
            ->willReturn($token);

        $this->session->method('exists')->willReturn(false);
        $this->session->method('get')->willReturn(null);

        $userSession = $this->createMock(IUserSession::class);

        $result = $this->backend->tryAutoLogin($userSession);

        $this->assertFalse($result);
    }

    public function testTryAutoLogin_UserNotFound_ReturnsFalse(): void
    {
        $config = $this->getDefaultConfig();

        $this->config->method('getSystemValue')
            ->with('nextcloud-app-cookieauth', null)
            ->willReturn($config);

        $payload = [
            'preferred_username' => 'nonexistent',
            'exp' => time() + 3600,
            'iss' => 'https://test.example.com/auth',
        ];

        $token = $this->createValidJwt($payload);

        $this->request->method('getCookie')
            ->with('authToken')
            ->willReturn($token);

        $this->session->method('exists')->willReturn(false);
        $this->session->method('get')->willReturn(null);

        $this->userManager->method('get')
            ->with('nonexistent')
            ->willReturn(null);

        $userSession = $this->createMock(IUserSession::class);

        $result = $this->backend->tryAutoLogin($userSession);

        $this->assertFalse($result);
    }

    public function testTryAutoLogin_DisabledUser_ReturnsFalse(): void
    {
        $config = $this->getDefaultConfig();

        $this->config->method('getSystemValue')
            ->with('nextcloud-app-cookieauth', null)
            ->willReturn($config);

        $payload = [
            'preferred_username' => 'disableduser',
            'exp' => time() + 3600,
            'iss' => 'https://test.example.com/auth',
        ];

        $token = $this->createValidJwt($payload);

        $this->request->method('getCookie')
            ->with('authToken')
            ->willReturn($token);

        $this->session->method('exists')->willReturn(false);
        $this->session->method('get')->willReturn(null);

        $user = $this->createMock(IUser::class);
        $user->method('isEnabled')->willReturn(false); // User disabled

        $this->userManager->method('get')
            ->with('disableduser')
            ->willReturn($user);

        $userSession = $this->createMock(IUserSession::class);

        $result = $this->backend->tryAutoLogin($userSession);

        $this->assertFalse($result);
    }

    public function testTryAutoLogin_AlgorithmMismatch_ReturnsFalse(): void
    {
        $config = $this->getDefaultConfig();
        $config['algorithm'] = 'RS512'; // Expect RS512

        $this->config->method('getSystemValue')
            ->with('nextcloud-app-cookieauth', null)
            ->willReturn($config);

        $payload = [
            'preferred_username' => 'testuser',
            'exp' => time() + 3600,
            'iss' => 'https://test.example.com/auth',
        ];

        // Create token with RS256 (wrong algorithm)
        $token = $this->createValidJwt($payload, 'RS256');

        $this->request->method('getCookie')
            ->with('authToken')
            ->willReturn($token);

        $this->session->method('exists')->willReturn(false);
        $this->session->method('get')->willReturn(null);

        $userSession = $this->createMock(IUserSession::class);

        $result = $this->backend->tryAutoLogin($userSession);

        $this->assertFalse($result);
    }

    public function testTryAutoLogin_InvalidTokenFormat_ReturnsFalse(): void
    {
        $config = $this->getDefaultConfig();

        $this->config->method('getSystemValue')
            ->with('nextcloud-app-cookieauth', null)
            ->willReturn($config);

        // Invalid token (not 3 parts)
        $this->request->method('getCookie')
            ->with('authToken')
            ->willReturn('invalid.token');

        $this->session->method('exists')->willReturn(false);
        $this->session->method('get')->willReturn(null);

        $userSession = $this->createMock(IUserSession::class);

        $result = $this->backend->tryAutoLogin($userSession);

        $this->assertFalse($result);
    }

    public function testTryAutoLogin_NestedClaim_ExtractsUsername(): void
    {
        $config = $this->getDefaultConfig();
        $config['user_claim'] = 'user.name'; // Nested claim

        $this->config->method('getSystemValue')
            ->with('nextcloud-app-cookieauth', null)
            ->willReturn($config);

        $payload = [
            'user' => [
                'name' => 'nesteduser',
            ],
            'exp' => time() + 3600,
            'iss' => 'https://test.example.com/auth',
        ];

        $token = $this->createValidJwt($payload);

        $this->request->method('getCookie')
            ->with('authToken')
            ->willReturn($token);

        $this->session->method('exists')->willReturn(false);
        $this->session->method('get')->willReturn(null);

        $user = $this->createMock(IUser::class);
        $user->method('isEnabled')->willReturn(true);

        $this->userManager->method('get')
            ->with('nesteduser')
            ->willReturn($user);

        $userSession = $this->createMock(IUserSession::class);
        $userSession->method('setUser')->willReturn(true);

        $result = $this->backend->tryAutoLogin($userSession);

        $this->assertTrue($result);
    }
}
