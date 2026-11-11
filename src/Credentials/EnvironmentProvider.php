<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Credentials;

use IndianOpinion\SigV4\Credentials;
use IndianOpinion\SigV4\Exception\ConfigurationException;
use IndianOpinion\SigV4\Exception\CredentialsNotFoundException;

/**
 * AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and optional AWS_SESSION_TOKEN.
 *
 * Neither key variable set: not found. Exactly one set: a configuration
 * error, because a half-configured environment must be loud.
 */
final class EnvironmentProvider implements Provider
{
    private readonly Environment $env;

    public function __construct(?Environment $env = null)
    {
        $this->env = $env ?? Environment::fromGlobals();
    }

    public function getCredentials(): Credentials
    {
        $key = $this->env->get('AWS_ACCESS_KEY_ID');
        $secret = $this->env->get('AWS_SECRET_ACCESS_KEY');
        if ($key === null && $secret === null) {
            throw new CredentialsNotFoundException('env: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are not set');
        }
        if ($key === null || $secret === null) {
            throw new ConfigurationException(sprintf(
                'env: %s is set but %s is not; set both or neither.',
                $key === null ? 'AWS_SECRET_ACCESS_KEY' : 'AWS_ACCESS_KEY_ID',
                $key === null ? 'AWS_ACCESS_KEY_ID' : 'AWS_SECRET_ACCESS_KEY',
            ));
        }

        return new Credentials($key, $secret, $this->env->get('AWS_SESSION_TOKEN'), null, 'env');
    }
}
