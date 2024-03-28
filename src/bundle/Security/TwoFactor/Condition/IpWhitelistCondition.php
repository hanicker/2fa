<?php

declare(strict_types=1);

namespace Scheb\TwoFactorBundle\Security\TwoFactor\Condition;

use Scheb\TwoFactorBundle\Security\TwoFactor\AuthenticationContextInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\IpWhitelist\IpWhitelistProviderInterface;
use Symfony\Component\HttpFoundation\IpUtils;

/**
 * @final
 */
class IpWhitelistCondition implements TwoFactorConditionInterface
{
    private IpWhitelistProviderInterface $ipWhitelistProvider;

    public function __construct(IpWhitelistProviderInterface $ipWhitelistProvider)
    {
        $this->ipWhitelistProvider = $ipWhitelistProvider;
    }

    public function shouldPerformTwoFactorAuthentication(AuthenticationContextInterface $context): bool
    {
        $request = $context->getRequest();
        $requestIp = $request->getClientIp();

        return null === $requestIp || !IpUtils::checkIp($requestIp, $this->ipWhitelistProvider->getWhitelistedIps($context));
    }
}
