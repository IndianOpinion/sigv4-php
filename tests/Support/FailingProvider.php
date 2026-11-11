<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests\Support;

use IndianOpinion\SigV4\Credentials;
use IndianOpinion\SigV4\Credentials\Provider;

/**
 * A provider that always throws the given exception, and counts calls.
 */
final class FailingProvider implements Provider
{
    public int $calls = 0;

    public function __construct(private readonly \Throwable $exception)
    {
    }

    public function getCredentials(): Credentials
    {
        $this->calls++;
        throw $this->exception;
    }
}
