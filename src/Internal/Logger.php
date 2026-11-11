<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Internal;

/**
 * Wraps the optional PSR-3-shaped logger callable.
 *
 * The callable receives (string $level, string $message, array $context).
 * A PSR-3 logger can be passed as `[$logger, 'log']`. Messages and context
 * never carry secret keys, session tokens or signing keys.
 *
 * @internal
 */
final class Logger
{
    /** @var (callable(string, string, array<string, mixed>): mixed)|null */
    private $callable;

    /**
     * @param (callable(string, string, array<string, mixed>): mixed)|null $callable
     */
    public function __construct(?callable $callable)
    {
        $this->callable = $callable;
    }

    /**
     * @param array<string, mixed> $context
     */
    public function debug(string $message, array $context = []): void
    {
        $this->log('debug', $message, $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function warning(string $message, array $context = []): void
    {
        $this->log('warning', $message, $context);
    }

    /**
     * @param array<string, mixed> $context
     */
    private function log(string $level, string $message, array $context): void
    {
        if ($this->callable !== null) {
            ($this->callable)($level, $message, $context);
        }
    }
}
