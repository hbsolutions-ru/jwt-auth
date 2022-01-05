<?php declare(strict_types=1);

namespace HBS\JwtAuth\Service;

use Psr\Log\LoggerInterface;
use Firebase\JWT\{
    ExpiredException,
    JWT as FirebaseJwt,
    Key,
};
use HBS\Helpers\{
    ObjectHelper,
    StringHelper,
};
use HBS\JwtAuth\{
    Exception\AuthenticationException,
    Immutable\Jwt as JwtData,
    Immutable\Settings,
    Meta\Info,
};

final class Jwt
{
    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @var Settings
     */
    private $settings;

    public function __construct(LoggerInterface $logger, Settings $settings)
    {
        $this->logger = $logger;
        $this->settings = $settings;
    }

    /**
     * Returns JWT
     *
     * @param array $userData
     * @return JwtData
     * @throws \Exception
     */
    public function signIn(array $userData = []): JwtData
    {
        // JWT ID
        $jti = StringHelper::randomBase62(16);

        // Issued At
        $iat = (new \DateTime())->getTimestamp();

        // Expiration Time
        $exp = (new \DateTime('@' . ($iat + $this->settings->expiration)))->getTimestamp();

        $payload = [
            'jti' => $jti,
            'iat' => $iat,
            'exp' => $exp,
            'data' => $userData,
        ];

        $jwt = FirebaseJwt::encode($payload, $this->settings->secret, $this->settings->algorithm);

        return new JwtData($jwt, $jti, $iat, $exp);
    }

    /**
     * Returns user data
     *
     * @param string $jwt
     * @return array
     */
    public function authenticate(string $jwt): array
    {
        try {
            $key = new Key($this->settings->secret, $this->settings->algorithm);
            $payload = ObjectHelper::toArray(
                FirebaseJwt::decode($jwt, $key)
            );
        } catch (ExpiredException $e) {
            throw $e;
        } catch (\LogicException $e) {
            throw $this->handleError($e);
        } catch (\RuntimeException $e) {
            throw $this->handleError($e);
        }

        if ($this->settings->dataKey && strlen($this->settings->dataKey)) {

            if (!isset($payload[$this->settings->dataKey])) {
                $this->logger->warning(sprintf("[%s] User data not found in the JWT", Info::PROJECT_NAME));

                throw new AuthenticationException('Invalid token');
            }

            return $payload[$this->settings->dataKey];
        }

        return $payload;
    }

    /**
     * Intercept and rethrow exception for security reasons
     *
     * @param \Exception $e
     * @return AuthenticationException
     */
    private function handleError(\Exception $e): AuthenticationException
    {
        $this->logger->error(sprintf(
            "[%s] Error! Type: %s; Code: %s; Message: %s; File: %s; Line: %s.",
            Info::PROJECT_NAME, get_class($e), (string)$e->getCode(), $e->getMessage(), $e->getFile(), $e->getLine()
        ));

        return new AuthenticationException('Invalid token');
    }
}
