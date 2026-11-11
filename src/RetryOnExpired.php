<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4;

use IndianOpinion\SigV4\Credentials\RefreshableProvider;
use IndianOpinion\SigV4\Http\HttpResponse;

/**
 * Sends a signed request; if AWS answers with an expired or unrecognised
 * credential error, refreshes the credentials once, re-signs and sends
 * exactly once more. Never twice. Any other answer is returned untouched.
 *
 * ```php
 * $retry = new RetryOnExpired($signer, $provider);
 * $response = $retry->send($request, 'eu-west-2', 'ses', function (SignedRequest $signed): HttpResponse {
 *     // send with your HTTP client, return new HttpResponse($status, $headers, $body)
 * });
 * ```
 */
final class RetryOnExpired
{
    public function __construct(
        private readonly Signer $signer,
        private readonly RefreshableProvider $provider,
    ) {
    }

    /**
     * @param callable(SignedRequest): HttpResponse $send
     */
    public function send(
        Request $request,
        string $region,
        string $service,
        callable $send,
        ?SigningOptions $options = null,
    ): HttpResponse {
        $signed = $this->signer->sign($request, $this->provider->getCredentials(), $region, $service, $options);
        $response = $send($signed);
        if (!ErrorInfo::fromHttpResponse($response)->isExpiredCredentials()) {
            return $response;
        }
        $signed = $this->signer->sign($request, $this->provider->refresh(), $region, $service, $options);

        return $send($signed);
    }
}
