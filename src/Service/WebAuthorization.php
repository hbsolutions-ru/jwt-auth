<?php declare(strict_types=1);

namespace HBS\JwtAuth\Service;

use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Log\LoggerInterface;
use HBS\JwtAuth\Exception\AuthenticationException;

final class WebAuthorization
{
    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @var Jwt
     */
    private $jwtService;

    /**
     * @var AuthorizationServiceInterface
     */
    private $authorizationService;

    public function __construct(
        LoggerInterface $logger,
        Jwt $jwtService,
        AuthorizationServiceInterface $authorizationService
    ) {
        $this->logger = $logger;
        $this->jwtService = $jwtService;
        $this->authorizationService = $authorizationService;
    }

    /**
     * Authenticate (by the HTTP Authorization header) and authorize user
     *
     * @param Request $request
     */
    public function authorize(Request $request): void
    {
        if (!preg_match("/Bearer\s+(.*)$/i", $request->getHeaderLine("Authorization"), $matches)) {
            throw new AuthenticationException('Authorization header not found or is not in the correct format');
        }

        try {
            $data = $this->jwtService->authenticate((string)$matches[1]);
        } catch (\RuntimeException $e) {
            throw new AuthenticationException($e->getMessage());
        }

        $this->authorizationService->authorize($data);
    }
}
