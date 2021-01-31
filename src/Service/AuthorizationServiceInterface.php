<?php declare(strict_types=1);

namespace HBS\JwtAuth\Service;

interface AuthorizationServiceInterface
{
    public function authorize(array $data);
}
