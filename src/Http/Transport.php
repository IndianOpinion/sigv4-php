<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Http;

/**
 * Sends credential-endpoint requests. The signer never uses a transport;
 * only the container and instance metadata providers do.
 *
 * Implementations must: never use a proxy, never follow redirects, keep TLS
 * verification on, honour both timeouts, and stop reading after
 * `maxResponseBytes + 1` bytes. A network failure is returned as
 * {@see HttpResponse::failure()}, not thrown.
 */
interface Transport
{
    public function send(HttpRequest $request): HttpResponse;
}
