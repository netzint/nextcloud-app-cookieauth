<?php

declare(strict_types=1);

return [
    'routes' => [
        // Auth status endpoints
        ['name' => 'auth#status', 'url' => '/status', 'verb' => 'GET'],
        ['name' => 'auth#debug', 'url' => '/debug', 'verb' => 'GET'],
        ['name' => 'auth#tokenCheck', 'url' => '/token-check', 'verb' => 'GET'],

        // Admin settings API endpoints
        ['name' => 'settings#save', 'url' => '/settings/save', 'verb' => 'POST'],
        ['name' => 'settings#testConnection', 'url' => '/settings/test', 'verb' => 'POST'],
        ['name' => 'settings#status', 'url' => '/settings/status', 'verb' => 'GET'],
        ['name' => 'settings#migrate', 'url' => '/settings/migrate', 'verb' => 'POST'],
    ],
];
