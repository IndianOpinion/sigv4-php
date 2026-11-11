<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Http;

/**
 * Transport on PHP streams, for hosts without curl. No proxy (the context
 * sets none, and the http wrapper ignores HTTP_PROXY), no redirects, TLS
 * verification on, explicit timeout, capped response size.
 *
 * The stream wrapper has a single timeout; it is set to the total timeout.
 */
final class StreamTransport implements Transport
{
    public function send(HttpRequest $request): HttpResponse
    {
        $context = stream_context_create($this->buildContextOptions($request));
        $warning = '';
        set_error_handler(static function (int $errno, string $message) use (&$warning): bool {
            $warning = $message;

            return true;
        });
        try {
            $stream = fopen($request->url, 'rb', false, $context);
            if ($stream === false) {
                return HttpResponse::failure(
                    $warning !== '' ? $warning : 'could not open the URL',
                    stripos($warning, 'timed out') !== false,
                );
            }
            $body = stream_get_contents($stream, $request->maxResponseBytes + 1);
            $meta = stream_get_meta_data($stream);
            fclose($stream);
        } finally {
            restore_error_handler();
        }
        if ($meta['timed_out']) {
            return HttpResponse::failure('read timed out', true);
        }
        if ($body === false) {
            return HttpResponse::failure($warning !== '' ? $warning : 'could not read the response');
        }

        $status = 0;
        $headers = [];
        $wrapper = $meta['wrapper_data'] ?? [];
        foreach (is_array($wrapper) ? $wrapper : [] as $line) {
            if (!is_string($line)) {
                continue;
            }
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m) === 1) {
                $status = (int) $m[1];
                $headers = [];
                continue;
            }
            $colon = strpos($line, ':');
            if ($colon !== false) {
                $headers[strtolower(trim(substr($line, 0, $colon)))][] = trim(substr($line, $colon + 1));
            }
        }
        if ($status === 0) {
            return HttpResponse::failure('no HTTP status line in the response');
        }

        return new HttpResponse($status, $headers, $body);
    }

    /**
     * The stream context options for a request. Public so the no-proxy and
     * no-redirect rules can be checked without a network.
     *
     * @internal
     *
     * @return array{http: array<string, mixed>, ssl: array<string, mixed>}
     */
    public function buildContextOptions(HttpRequest $request): array
    {
        $lines = [];
        foreach ($request->headers as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }
        $lines[] = 'Connection: close';

        return [
            'http' => [
                'method' => $request->method,
                'header' => implode("\r\n", $lines),
                'content' => $request->body,
                'timeout' => $request->timeout,
                'ignore_errors' => true,
                'follow_location' => 0,
                'max_redirects' => 1,
                'protocol_version' => 1.1,
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'allow_self_signed' => false,
            ],
        ];
    }
}
