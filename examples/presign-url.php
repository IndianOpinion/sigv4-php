<?php

/**
 * Presign an S3 GET and an S3 PUT.
 *
 * Run: php examples/presign-url.php
 *
 * Nothing is sent. The bucket endpoint and keys are fake.
 */

declare(strict_types=1);

use IndianOpinion\SigV4\Credentials;
use IndianOpinion\SigV4\Request;
use IndianOpinion\SigV4\Signer;
use IndianOpinion\SigV4\SigningOptions;

require is_file(__DIR__ . '/../vendor/autoload.php')
    ? __DIR__ . '/../vendor/autoload.php'
    : __DIR__ . '/../bootstrap.php';

$credentials = new Credentials('AKIDEXAMPLE', 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY');
$signer = new Signer();

// A download link valid for one hour. fromRawPath() encodes the key for
// you, so a key with spaces or unicode is never encoded twice.
$download = $signer->presign(
    Request::fromRawPath('GET', 'https://example-bucket.storage.example.com', 'reports/2026/annual report.pdf'),
    $credentials,
    'eu-west-2',
    's3',
    3600,
);
echo "GET link (", $download->getEffectiveExpires(), " s):\n", $download->getUrl(), "\n\n";

// An upload link that pins the content type. Whoever uploads must send
// exactly these headers.
$upload = $signer->presign(
    Request::fromRawPath(
        'PUT',
        'https://example-bucket.storage.example.com',
        'uploads/photo.jpg',
        [],
        ['Content-Type' => 'image/jpeg'],
    ),
    $credentials,
    'eu-west-2',
    's3',
    600,
    new SigningOptions(signHeaders: ['content-type']),
);
echo "PUT link:\n", $upload->getUrl(), "\n";
foreach ($upload->getHeadersToSend() as [$name, $value]) {
    echo "  must send: ", $name, ': ', $value, "\n";
}
