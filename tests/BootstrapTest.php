<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests;

use PHPUnit\Framework\TestCase;

/**
 * The library works with one require of bootstrap.php and no Composer.
 */
final class BootstrapTest extends TestCase
{
    public function testEveryClassLoadsThroughTheBootstrapAlone(): void
    {
        $script = <<<'PHP'
            require $argv[1];
            $loaded = 0;
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($argv[2], FilesystemIterator::SKIP_DOTS));
            foreach ($it as $file) {
                $relative = substr($file->getPathname(), strlen($argv[2]) + 1, -4);
                $class = 'IndianOpinion\\SigV4\\' . str_replace('/', '\\', $relative);
                if ($relative === 'Psr7/Psr7Adapter') {
                    continue;
                }
                if (!class_exists($class) && !interface_exists($class)) {
                    fwrite(STDERR, "missing $class\n");
                    exit(1);
                }
                $loaded++;
            }
            $signer = new IndianOpinion\SigV4\Signer(new IndianOpinion\SigV4\Clock\FrozenClock('2015-08-30T12:36:00Z'));
            $signed = $signer->sign(
                new IndianOpinion\SigV4\Request('GET', 'https://example.amazonaws.com/'),
                new IndianOpinion\SigV4\Credentials('AKIDEXAMPLE', 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'),
                'us-east-1',
                'service',
            );
            echo $loaded, ' ', $signed->getDetails()->getSignature();
            PHP;
        $root = dirname(__DIR__);
        $command = sprintf(
            '%s -n -d extension_dir=%s -r %s %s %s 2>&1',
            escapeshellarg(PHP_BINARY),
            escapeshellarg((string) ini_get('extension_dir')),
            escapeshellarg($script),
            escapeshellarg($root . '/bootstrap.php'),
            escapeshellarg($root . '/src'),
        );
        $output = [];
        $code = 0;
        exec($command, $output, $code);
        self::assertSame(0, $code, implode("\n", $output));
        self::assertMatchesRegularExpression(
            '/^\d+ 5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31$/',
            implode("\n", $output),
        );
    }
}
