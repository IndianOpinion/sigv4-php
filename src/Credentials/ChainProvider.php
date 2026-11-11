<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Credentials;

use IndianOpinion\SigV4\Credentials;
use IndianOpinion\SigV4\Exception\ConfigurationException;
use IndianOpinion\SigV4\Exception\CredentialsNotFoundException;
use IndianOpinion\SigV4\Internal\Logger;

/**
 * Tries providers in order; the first to return credentials wins.
 *
 * "Not found" moves to the next provider. Any other exception stops the
 * chain and is raised: silently falling through to a different identity is
 * worse than failing. When every provider declines, the exception lists
 * each one and its reason.
 */
final class ChainProvider implements Provider
{
    /** @var list<Provider> */
    private readonly array $providers;
    private readonly Logger $logger;

    /**
     * @param list<Provider> $providers
     * @param (callable(string, string, array<string, mixed>): mixed)|null $logger
     */
    public function __construct(array $providers, ?callable $logger = null)
    {
        if ($providers === []) {
            throw new ConfigurationException('A provider chain needs at least one provider.');
        }
        $this->providers = $providers;
        $this->logger = new Logger($logger);
    }

    public function getCredentials(): Credentials
    {
        $reasons = [];
        foreach ($this->providers as $provider) {
            try {
                $credentials = $provider->getCredentials();
                $this->logger->debug('Credential provider answered', [
                    'provider' => $credentials->getSource(),
                    'accessKeyId' => $credentials->getAccessKeyId(),
                ]);

                return $credentials;
            } catch (CredentialsNotFoundException $e) {
                foreach ($e->getReasons() as $reason) {
                    $reasons[] = $reason;
                }
            }
        }

        throw new CredentialsNotFoundException(
            'No AWS credentials found. Tried: ' . implode('; ', $reasons) . '.',
            $reasons,
        );
    }

    /**
     * @return list<Provider>
     */
    public function getProviders(): array
    {
        return $this->providers;
    }
}
