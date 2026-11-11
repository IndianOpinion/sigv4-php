<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Credentials;

use IndianOpinion\SigV4\Credentials;
use IndianOpinion\SigV4\Exception\ConfigurationException;
use IndianOpinion\SigV4\Exception\CredentialsException;
use IndianOpinion\SigV4\Exception\CredentialsNotFoundException;

/**
 * Something that resolves credentials.
 */
interface Provider
{
    /**
     * @throws CredentialsNotFoundException when this provider does not apply here (a chain moves on)
     * @throws ConfigurationException when the configuration is wrong or unsafe (a chain stops)
     * @throws CredentialsException when the provider applies but failed (a chain stops)
     */
    public function getCredentials(): Credentials;
}
