<?php declare(strict_types=1);

namespace HBS\JwtAuth\Middleware;

use Psr\Http\Message\{
    ResponseInterface as Response,
    ResponseFactoryInterface,
    ServerRequestInterface as Request,
};
use Psr\Http\Server\{
    MiddlewareInterface,
    RequestHandlerInterface as RequestHandler,
};
use Psr\Log\{
    LoggerInterface,
    NullLogger,
};
use HBS\JwtAuth\{
    Meta\Info,
    Service\WebAuthorization,
};

final class JwtAuthMiddleware implements MiddlewareInterface
{
    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @var ResponseFactoryInterface
     */
    protected $factory;

    /**
     * @var WebAuthorization
     */
    protected $service;

    public function __construct(
        ResponseFactoryInterface $factory,
        WebAuthorization $service,
        LoggerInterface $logger = null
    ) {
        $this->factory = $factory;
        $this->service = $service;
        $this->logger = $logger ?: new NullLogger();
    }

    public function process(Request $request, RequestHandler $handler): Response
    {
        try {
            $this->service->authorize($request);
        } catch (\RuntimeException $e) {
            $this->logger->debug(
                sprintf("[%s] Auth failed in Middleware: %s", Info::PROJECT_NAME, $e->getMessage())
            );
            return $this->unauthorized();
        }

        return $handler->handle($request);
    }

    private function unauthorized(): Response
    {
        $response = $this->factory->createResponse();
        return $response
            ->withHeader('WWW-Authenticate', 'Basic realm="Access to the app"')
            ->withStatus(401);
    }
}
