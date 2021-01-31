# jwt-auth
Service for JWT authentication.

## Installation
`composer require hbsolutions/jwt-auth`

## Usage
Namespace: `HBS\JwtAuth`

### JWT Authentication
Service class name: `HBS\JwtAuth\Service\Jwt`

Needs to inject into constructor:

Object | Type (instance of)
--- | ---
Logger | `Psr\Log\LoggerInterface`
Settings | `HBS\JwtAuth\Immutable\Settings`

Throws `HBS\JwtAuth\Exception\AuthenticationException` &ndash; child of the `\RuntimeException`.

### Web Authorization
Service class name: `HBS\JwtAuth\Service\WebAuthorization`

Needs to inject into constructor:

Object | Type (instance of)
--- | ---
Logger | `Psr\Log\LoggerInterface`
JWT Service | `HBS\JwtAuth\Service\Jwt`
Authorization Service | `HBS\JwtAuth\Service\AuthorizationServiceInterface`
