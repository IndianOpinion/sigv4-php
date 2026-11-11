<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Psr7;

use IndianOpinion\SigV4\Exception\ConfigurationException;
use IndianOpinion\SigV4\Exception\InvalidRequestException;
use IndianOpinion\SigV4\Payload;
use IndianOpinion\SigV4\PresignedUrl;
use IndianOpinion\SigV4\Request;
use IndianOpinion\SigV4\SignedRequest;
use Psr\Http\Message\RequestInterface;

/**
 * Converts between PSR-7 requests and this library's Request. Works only
 * when the PSR-7 interfaces are installed; the library does not depend on
 * them.
 */
final class Psr7Adapter
{
    /**
     * @param object $request a Psr\Http\Message\RequestInterface
     * @param Payload|null $payload overrides the body (use a precomputed hash for a large stream)
     *
     * @throws ConfigurationException when PSR-7 is not installed
     * @throws InvalidRequestException when the object is not a PSR-7 request
     */
    public static function fromPsr7(object $request, ?Payload $payload = null): Request
    {
        $psr = self::assertRequest($request);
        $headers = [];
        foreach ($psr->getHeaders() as $name => $values) {
            foreach ($values as $value) {
                $headers[] = [(string) $name, $value];
            }
        }
        if ($payload === null) {
            $body = $psr->getBody();
            if ($body->isSeekable()) {
                $body->rewind();
            }
            $payload = Payload::fromString($body->getContents());
            if ($body->isSeekable()) {
                $body->rewind();
            }
        }

        return new Request($psr->getMethod(), (string) $psr->getUri(), $headers, $payload);
    }

    /**
     * Copies the signing headers of a SignedRequest onto a PSR-7 request.
     *
     * @param object $request a Psr\Http\Message\RequestInterface
     *
     * @return RequestInterface
     */
    public static function applyTo(object $request, SignedRequest $signed): object
    {
        $psr = self::assertRequest($request);
        $grouped = [];
        foreach ($signed->getHeaders() as [$name, $value]) {
            $grouped[strtolower($name)][0] = $name;
            $grouped[strtolower($name)][1][] = $value;
        }
        foreach ($grouped as [$name, $values]) {
            $psr = $psr->withHeader($name, $values);
        }

        return $psr;
    }

    /**
     * The presigned URL as a PSR-7 request: the URL, plus the extra signed
     * headers the user of the URL must send.
     *
     * @param object $request a Psr\Http\Message\RequestInterface to base the result on
     *
     * @return RequestInterface
     */
    public static function applyPresigned(object $request, PresignedUrl $presigned): object
    {
        $psr = self::assertRequest($request);
        $psr = $psr->withUri($psr->getUri()->withQuery((string) parse_url($presigned->getUrl(), PHP_URL_QUERY)));
        foreach ($presigned->getHeadersToSend() as [$name, $value]) {
            $psr = $psr->withHeader($name, $value);
        }

        return $psr;
    }

    private static function assertRequest(object $request): RequestInterface
    {
        if (!interface_exists(RequestInterface::class)) {
            throw new ConfigurationException('PSR-7 is not installed: require psr/http-message to use the adapter.');
        }
        if (!$request instanceof RequestInterface) {
            throw new InvalidRequestException('Expected a Psr\Http\Message\RequestInterface.');
        }

        return $request;
    }
}
