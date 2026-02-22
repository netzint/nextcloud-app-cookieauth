<?php

declare(strict_types=1);

namespace OCA\CookieAuth\Settings;

use OCA\CookieAuth\Service\ConfigService;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\IL10N;
use OCP\Settings\ISettings;

/**
 * Admin settings page for Cookie Auth configuration
 */
class Admin implements ISettings
{
    public function __construct(
        private ConfigService $configService,
        private IL10N $l10n,
    ) {
    }

    /**
     * @return TemplateResponse
     */
    public function getForm(): TemplateResponse
    {
        $config = $this->configService->getAll();

        // Determine config sources for each setting
        $configSources = [];
        foreach (array_keys($config) as $key) {
            $configSources[$key] = $this->configService->getConfigSource($key);
        }

        $parameters = [
            'config' => $config,
            'configSources' => $configSources,
            'isLegacyMode' => $this->configService->isLegacyMode(),
            'algorithms' => ['RS256', 'RS384', 'RS512'],
        ];

        return new TemplateResponse(
            'nextcloud-app-cookieauth',
            'admin',
            $parameters,
            ''
        );
    }

    /**
     * @return string the section ID (security section)
     */
    public function getSection(): string
    {
        return 'security';
    }

    /**
     * @return int priority within section (0-100, lower = higher on page)
     */
    public function getPriority(): int
    {
        return 50;
    }
}
