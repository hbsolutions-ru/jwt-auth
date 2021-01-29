# jwt-auth
Service for JWT authentication.

## Installation
`composer require hbsolutions/jwt-auth`

## Usage
Namespace: `HBS\JwtAuth`

Service class name: `HBS\JwtAuth\Service\Jwt`

Needs to inject into constructor:
- `Psr\Log\LoggerInterface`
- `HBS\JwtAuth\Immutable\Settings`

Throws `HBS\JwtAuth\Exception\AuthenticationException` &ndash; child of the `\RuntimeException`.
