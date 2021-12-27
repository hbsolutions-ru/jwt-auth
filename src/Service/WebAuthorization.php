<?php declare(strict_types=1);

namespace HBS\JwtAuth\Service;

use Psr\Http\Message\ServerRequestInterface as Request;
use HBS\JwtAuth\Exception\AuthenticationException;

final class WebAuthorization
{
    /**
     * @var Jwt
     */
    private $jwtService;

    /**
     * @var AuthorizationServiceInterface
     */
    private $authorizationService;

    public function __construct(Jwt $jwtService, AuthorizationServiceInterface $authorizationService)
    {
        $this->jwtService = $jwtService;
        $this->authorizationService = $authorizationService;
    }

    /**
     * Authenticate (by the HTTP Authorization header or query param) and authorize user
     *
     * @param Request $request
     */
    public function authorize(Request $request): void
    {
        $jwt = null;

        // Try authorization header
        if (preg_match("/Bearer\s+(.*)$/i", $request->getHeaderLine("Authorization"), $matches)) {
            $jwt = (string)$matches[1];
        }

        // Try query param
        if (!$jwt && isset($request->getQueryParams()['jwt'])) {
            $jwt = $request->getQueryParams()['jwt'];
        }

        if (empty($jwt)) {
            throw new AuthenticationException('Authorization header not found or is not in the correct format');
        }

        try {
            $data = $this->jwtService->authenticate($jwt);
        } catch (\RuntimeException $e) {
            throw new AuthenticationException($e->getMessage());
        }

        $this->authorizationService->authorize($data);
    }
}
