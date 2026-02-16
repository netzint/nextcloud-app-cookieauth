<?php

declare(strict_types=1);

return [
    'routes' => [
        // Optional: Endpoint to check auth status
        ['name' => 'auth#status', 'url' => '/status', 'verb' => 'GET'],
        // Debug endpoint with more details
        ['name' => 'auth#debug', 'url' => '/debug', 'verb' => 'GET'],
    ],
];
