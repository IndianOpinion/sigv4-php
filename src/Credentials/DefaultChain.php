<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Credentials;

use IndianOpinion\SigV4\Cache\EncryptedCache;
use IndianOpinion\SigV4\Clock\Clock;
use IndianOpinion\SigV4\Credentials;
use IndianOpinion\SigV4\Http\Transport;

/**
 * Builds the default chain: static (when given), environment, container,
 * instance metadata, wrapped in a caching provider.
 */
final class DefaultChain
{
    /**
     * @param Credentials|null $static explicit credentials, tried first
     * @param EncryptedCache|null $sharedCache optional encrypted shared cache
     * @param bool $useInstanceMetadata false drops IMDS from the chain (recommended off EC2)
     * @param (callable(string, string, array<string, mixed>): mixed)|null $logger
     */
    public static function create(
        ?Credentials $static = null,
        ?EncryptedCache $sharedCache = null,
        ?Clock $clock = null,
        ?callable $logger = null,
        ?Environment $env = null,
        ?Transport $transport = null,
        bool $useInstanceMetadata = true,
        ?string $roleName = null,
        int $marginSeconds = CachingProvider::DEFAULT_MARGIN,
        string $cacheKey = CachingProvider::DEFAULT_CACHE_KEY,
    ): CachingProvider {
        $env ??= Environment::fromGlobals();
        $providers = [];
        if ($static !== null) {
            $providers[] = new StaticProvider($static);
        }
        $providers[] = new EnvironmentProvider($env);
        $providers[] = new ContainerProvider($env, $transport, $clock, $logger);
        if ($useInstanceMetadata) {
            $providers[] = new InstanceMetadataProvider($env, $transport, $clock, $logger, roleName: $roleName);
        }

        return new CachingProvider(
            new ChainProvider($providers, $logger),
            $sharedCache,
            $clock,
            $logger,
            marginSeconds: $marginSeconds,
            cacheKey: $cacheKey,
        );
    }
}
