<?php declare(strict_types=1);

namespace HBS\JwtAuth\Immutable;

/**
 * Immutable Settings
 *
 * @package HBS\JwtAuth\Immutable
 * @property string $algorithm The signing algorithm
 * @property int $expiration JWT expiration time in seconds
 * @property string $secret The secret key
 * @property string $dataKey The key of the object with user's data in the payload
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

    /**
     * @var string
     */
    protected $_dataKey;

    public function __construct(
        string $algorithm,
        int $expiration,
        string $secret,
        string $dataKey = 'data'
    ) {
        $this->_algorithm = $algorithm;
        $this->_expiration = $expiration;
        $this->_secret = $secret;
        $this->_dataKey = $dataKey;
    }
}
