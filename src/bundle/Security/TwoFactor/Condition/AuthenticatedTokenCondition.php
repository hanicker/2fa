<?php

declare(strict_types=1);

namespace Scheb\TwoFactorBundle\Security\TwoFactor\Condition;

use Scheb\TwoFactorBundle\Security\TwoFactor\AuthenticationContextInterface;
use function in_array;

/**
 * @final
 */
class AuthenticatedTokenCondition implements TwoFactorConditionInterface
{
    /**
     * @var string[]
     */
    private array $supportedTokens;

    /**
     * @param string[] $supportedTokens
     */
    public function __construct(array $supportedTokens)
    {
        $this->supportedTokens = $supportedTokens;
    }

    public function shouldPerformTwoFactorAuthentication(AuthenticationContextInterface $context): bool
    {
        $token = $context->getToken();

        return in_array(get_class($token), $this->supportedTokens, true);
    }
}
