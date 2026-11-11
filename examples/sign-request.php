<?php

/**
 * Sign a request with the Authorization header variant.
 *
 * Run: php examples/sign-request.php
 *
 * Nothing is sent. The endpoint and keys are fake; the script prints the
 * headers you would hand to your HTTP client.
 */

declare(strict_types=1);

use IndianOpinion\SigV4\Credentials;
use IndianOpinion\SigV4\Credentials\StaticProvider;
use IndianOpinion\SigV4\Request;
use IndianOpinion\SigV4\Signer;

require is_file(__DIR__ . '/../vendor/autoload.php')
    ? __DIR__ . '/../vendor/autoload.php'
    : __DIR__ . '/../bootstrap.php';

// In production, use the chain instead of static keys:
//     $provider = IndianOpinion\SigV4\Credentials\DefaultChain::create();
//     $credentials = $provider->getCredentials();
$provider = new StaticProvider(new Credentials('AKIDEXAMPLE', 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'));
$credentials = $provider->getCredentials();

// A JSON-protocol call to a fake endpoint.
$request = new Request(
    'POST',
    'https://queue.example.com/',
    [
        'Content-Type' => 'application/x-amz-json-1.0',
        'X-Amz-Target' => 'AmazonSQS.ListQueues',
    ],
    '{}',
);

$signer = new Signer();
$signed = $signer->sign($request, $credentials, 'eu-west-2', 'sqs');

echo $signed->getMethod(), ' ', $signed->getUrl(), "\n";
foreach ($signed->getHeaderLines() as $line) {
    echo $line, "\n";
}
echo "\n", $signed->getBody(), "\n\n";

// To send it with curl:
//     $ch = curl_init($signed->getUrl());
//     curl_setopt_array($ch, [
//         CURLOPT_CUSTOMREQUEST => $signed->getMethod(),
//         CURLOPT_HTTPHEADER => $signed->getHeaderLines(),
//         CURLOPT_POSTFIELDS => $signed->getBody(),
//         CURLOPT_RETURNTRANSFER => true,
//     ]);

// When AWS answers 403 SignatureDoesNotMatch, compare this with the
// canonical request in the error body:
echo "Canonical request:\n", $signed->getDetails()->getRedactedCanonicalRequest(), "\n";
