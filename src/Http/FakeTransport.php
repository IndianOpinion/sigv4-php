<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Http;

/**
 * An in-memory transport for tests: records every request and replays
 * scripted responses in order.
 *
 * A scripted entry is an HttpResponse, or a callable that receives the
 * HttpRequest and returns one.
 */
final class FakeTransport implements Transport
{
    /** @var list<HttpResponse|callable(HttpRequest): HttpResponse> */
    private array $queue;

    /** @var list<HttpRequest> */
    private array $requests = [];

    /**
     * @param list<HttpResponse|callable(HttpRequest): HttpResponse> $responses
     */
    public function __construct(array $responses = [])
    {
        $this->queue = $responses;
    }

    /**
     * @param HttpResponse|callable(HttpRequest): HttpResponse $response
     */
    public function push(HttpResponse|callable $response): void
    {
        $this->queue[] = $response;
    }

    public function send(HttpRequest $request): HttpResponse
    {
        $this->requests[] = $request;
        $next = array_shift($this->queue);
        if ($next === null) {
            throw new \LogicException(sprintf(
                'FakeTransport has no scripted response for %s %s.',
                $request->method,
                $request->url,
            ));
        }

        return $next instanceof HttpResponse ? $next : $next($request);
    }

    /**
     * @return list<HttpRequest>
     */
    public function getRequests(): array
    {
        return $this->requests;
    }

    public function count(): int
    {
        return count($this->requests);
    }

    public function remaining(): int
    {
        return count($this->queue);
    }
}
