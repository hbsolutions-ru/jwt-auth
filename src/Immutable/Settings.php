<?php declare(strict_types=1);

namespace HBS\JwtAuth\Immutable;

/**
 * Immutable Settings
 *
 * @package HBS\JwtAuth\Immutable
 * @property string $algorithm The signing algorithm
 * @property int $expiration JWT expiration time in seconds
 * @property string $secret The secret key
 */
final class Settings extends ImmutableAbstract
{
    /**
     * @var string
     */
    protected $_algorithm;

    /**
     * @var int
     */
    protected $_expiration;

    /**
     * @var string
     */
    protected $_secret;

    public function __construct(
        string $algorithm,
        int $expiration,
        string $secret
    ) {
        $this->_algorithm = $algorithm;
        $this->_expiration = $expiration;
        $this->_secret = $secret;
    }
}
