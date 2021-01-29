<?php declare(strict_types=1);

namespace HBS\JwtAuth\Immutable;

/**
 * Immutable Jwt
 *
 * @package HBS\JwtAuth\Immutable
 * @property string $jwt
 * @property string $jti JWT ID
 * @property int $iat Issued At
 * @property int $exp Expiration Time
 */
final class Jwt extends ImmutableAbstract
{
    /**
     * @var string
     */
    protected $_jwt;

    /**
     * @var string
     */
    protected $_jti;

    /**
     * @var int
     */
    protected $_iat;

    /**
     * @var int
     */
    protected $_exp;

    public function __construct(
        string $jwt,
        string $jti,
        int $iat,
        int $exp
    ) {
        $this->_jwt = $jwt;
        $this->_jti = $jti;
        $this->_iat = $iat;
        $this->_exp = $exp;
    }
}
