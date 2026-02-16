<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

// Register autoloader for OCP classes (nextcloud/ocp doesn't have autoload config)
spl_autoload_register(function ($class) {
    // Handle OCP namespace
    if (str_starts_with($class, 'OCP\\')) {
        $relativePath = str_replace('\\', '/', substr($class, 4));
        $file = __DIR__ . '/../vendor/nextcloud/ocp/OCP/' . $relativePath . '.php';
        if (file_exists($file)) {
            require_once $file;
            return true;
        }
    }
    // Handle NCU namespace
    if (str_starts_with($class, 'NCU\\')) {
        $relativePath = str_replace('\\', '/', substr($class, 4));
        $file = __DIR__ . '/../vendor/nextcloud/ocp/NCU/' . $relativePath . '.php';
        if (file_exists($file)) {
            require_once $file;
            return true;
        }
    }
    return false;
});
