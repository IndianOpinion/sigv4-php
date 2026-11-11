<?php

declare(strict_types=1);

namespace IndianOpinion\SigV4\Exception;

/**
 * A provider applies but failed (bad response, refused request, missing role). Chains stop here.
 */
final class CredentialsException extends SigV4Exception
{
}
