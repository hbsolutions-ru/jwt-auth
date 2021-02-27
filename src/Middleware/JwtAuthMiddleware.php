<?php declare(strict_types=1);

namespace HBS\JwtAuth\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use HBS\JwtAuth\Service\WebAuthorization;

final class JwtAuthMiddleware implements MiddlewareInterface
{
    /**
     * @var ResponseFactoryInterface
     */
    protected $factory;

    /**
     * @var WebAuthorization
     */
    protected $service;

    public function __construct(ResponseFactoryInterface $factory, WebAuthorization $service)
    {
        $this->factory = $factory;
        $this->service = $service;
    }

    public function process(Request $request, RequestHandler $handler): ResponseInterface
    {
        try {
            $this->service->authorize($request);
        } catch (\RuntimeException $e) {
            return $this->unauthorized();
        }

        return $handler->handle($request);
    }

    private function unauthorized(): ResponseInterface
    {
        $response = $this->factory->createResponse();
        return $response
            ->withHeader('WWW-Authenticate', 'Basic realm="Access to the app"')
            ->withStatus(401);
    }
}
