<?php

/**
 * Use sigv4-php without Composer:
 *
 *     require __DIR__ . '/sigv4-php/bootstrap.php';
 *
 * Registers a PSR-4 autoloader for the IndianOpinion\SigV4 namespace and
 * does nothing else.
 */

declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    $prefix = 'IndianOpinion\\SigV4\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $file = __DIR__ . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (is_file($file)) {
        require $file;
    }
});
