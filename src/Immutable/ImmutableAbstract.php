<?php declare(strict_types=1);

namespace HBS\JwtAuth\Immutable;

abstract class ImmutableAbstract
{
    public function __get(string $name)
    {
        return property_exists($this, "_{$name}") ? $this->{"_{$name}"} : null;
    }
}
