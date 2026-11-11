<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Credentials;

use IndianOpinion\SigV4\Credentials;

/**
 * A provider that caches, and can be told to throw its cache away.
 */
interface RefreshableProvider extends Provider
{
    /**
     * Fetches fresh credentials, bypassing every cache, and stores them in
     * every cache. Use after AWS answered with an expired-token error.
     */
    public function refresh(): Credentials;
}
