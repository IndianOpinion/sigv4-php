<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Http;

use IndianOpinion\SigV4\Exception\TransportException;

/**
 * Transport on the curl extension: no proxy (even with HTTP_PROXY set), no
 * redirects, TLS verification on, explicit timeouts, capped response size.
 */
final class CurlTransport implements Transport
{
    public function __construct()
    {
        if (!extension_loaded('curl')) {
            throw new TransportException('The curl extension is not loaded.');
        }
    }

    public function send(HttpRequest $request): HttpResponse
    {
        $handle = curl_init();
        $body = '';
        $headers = [];
        $overflow = false;
        $limit = $request->maxResponseBytes + 1;

        $options = $this->buildOptions($request);
        $options[CURLOPT_HEADERFUNCTION] = static function ($ch, string $line) use (&$headers): int {
            $colon = strpos($line, ':');
            if ($colon !== false) {
                $name = strtolower(trim(substr($line, 0, $colon)));
                $headers[$name][] = trim(substr($line, $colon + 1));
            }

            return strlen($line);
        };
        $options[CURLOPT_WRITEFUNCTION] = static function ($ch, string $chunk) use (&$body, &$overflow, $limit): int {
            $room = $limit - strlen($body);
            if (strlen($chunk) > $room) {
                $body .= substr($chunk, 0, max(0, $room));
                $overflow = true;

                return 0;
            }
            $body .= $chunk;

            return strlen($chunk);
        };
        curl_setopt_array($handle, $options);
        $ok = curl_exec($handle);
        $errno = curl_errno($handle);
        $error = curl_error($handle);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        curl_close($handle);

        if ($ok === false && !($overflow && $status > 0)) {
            return HttpResponse::failure(
                $error !== '' ? $error : 'curl error ' . $errno,
                $errno === CURLE_OPERATION_TIMEDOUT,
            );
        }

        /** @var array<string, list<string>> $headers */
        return new HttpResponse($status, $headers, $body);
    }

    /**
     * The curl options for a request, without the callbacks. Public so the
     * no-proxy and no-redirect rules can be checked without a network.
     *
     * @internal
     *
     * @return array<int, mixed>
     */
    public function buildOptions(HttpRequest $request): array
    {
        $lines = [];
        foreach ($request->headers as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }
        // Stop curl adding "Expect: 100-continue" to requests with a body.
        $lines[] = 'Expect:';

        $options = [
            CURLOPT_URL => $request->url,
            CURLOPT_CUSTOMREQUEST => $request->method,
            CURLOPT_HTTPHEADER => $lines,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0,
            CURLOPT_PROXY => '',
            CURLOPT_NOPROXY => '*',
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT_MS => (int) ceil($request->connectTimeout * 1000),
            CURLOPT_TIMEOUT_MS => (int) ceil($request->timeout * 1000),
            CURLOPT_NOSIGNAL => true,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        ];
        if ($request->body !== '') {
            $options[CURLOPT_POSTFIELDS] = $request->body;
        } elseif ($request->method === 'GET') {
            $options[CURLOPT_HTTPGET] = true;
        }

        return $options;
    }
}
