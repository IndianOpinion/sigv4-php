<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Tests\Support;

use IndianOpinion\SigV4\Clock\FrozenClock;
use IndianOpinion\SigV4\Credentials;
use IndianOpinion\SigV4\Credentials\Provider;

/**
 * Hands out numbered temporary credentials that expire a fixed time after the clock's current time.
 */
final class CountingProvider implements Provider
{
    public int $calls = 0;

    public function __construct(
        private readonly FrozenClock $clock,
        private readonly int $lifetime,
        private readonly string $prefix = 'AKIDCOUNT',
    ) {
    }

    public function getCredentials(): Credentials
    {
        $this->calls++;

        return new Credentials(
            $this->prefix . $this->calls,
            'secret-' . $this->calls,
            'token-' . $this->calls,
            $this->clock->now()->modify('+' . $this->lifetime . ' seconds'),
            'imds',
        );
    }
}
