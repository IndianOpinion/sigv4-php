<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Http;

use IndianOpinion\SigV4\Exception\TransportException;

/**
 * Picks the default transport: curl when loaded, else PHP streams.
 */
final class TransportFactory
{
    /**
     * @param bool|null $curlAvailable null detects; a boolean overrides (for tests)
     * @param bool|null $urlFopenAvailable null detects; a boolean overrides (for tests)
     *
     * @throws TransportException when neither curl nor allow_url_fopen is available
     */
    public static function create(?bool $curlAvailable = null, ?bool $urlFopenAvailable = null): Transport
    {
        if ($curlAvailable ?? extension_loaded('curl')) {
            return new CurlTransport();
        }
        if ($urlFopenAvailable ?? filter_var(ini_get('allow_url_fopen'), FILTER_VALIDATE_BOOLEAN)) {
            return new StreamTransport();
        }
        throw new TransportException(
            'No HTTP transport is available: install the curl extension or enable allow_url_fopen.'
        );
    }
}
