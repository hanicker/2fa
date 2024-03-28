<?php

declare(strict_types=1);

namespace Scheb\TwoFactorBundle\Security\TwoFactor\Condition;

use Scheb\TwoFactorBundle\Security\TwoFactor\AuthenticationContextInterface;

/**
 * @final
 */
class TwoFactorConditionRegistry
{
    /**
     * @var iterable|TwoFactorConditionInterface[]
     */
    private iterable $conditions;

    /**
     * @param TwoFactorConditionInterface[] $conditions
     */
    public function __construct(iterable $conditions)
    {
        $this->conditions = $conditions;
    }

    public function shouldPerformTwoFactorAuthentication(AuthenticationContextInterface $context): bool
    {
        foreach ($this->conditions as $condition) {
            if (!$condition->shouldPerformTwoFactorAuthentication($context)) {
                return false;
            }
        }

        return true;
    }
}
