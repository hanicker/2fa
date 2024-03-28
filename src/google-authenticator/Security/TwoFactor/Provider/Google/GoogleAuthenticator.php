<?php

declare(strict_types=1);

namespace Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Google;

use ParagonIE\ConstantTime\Base32;
use Scheb\TwoFactorBundle\Model\Google\TwoFactorInterface;
use function random_bytes;
use function str_replace;
use function strlen;

/**
 * @final
 */
class GoogleAuthenticator implements GoogleAuthenticatorInterface
{
    private GoogleTotpFactory $totpFactory;
    private int $window;
    /**
     * @var mixed
     */
    private $leeway;

    public function __construct(
        GoogleTotpFactory $totpFactory,
        /** @var 0|positive-int */
        int $window,
        /** @var 0|positive-int|null */
        $leeway
    ) {
        $this->totpFactory = $totpFactory;
        $this->window = $window;
        $this->leeway = $leeway;
    }

    public function checkCode(TwoFactorInterface $user, string $code): bool
    {
        // Strip any user added spaces
        $code = str_replace(' ', '', $code);
        if (0 === strlen($code)) {
            return false;
        }

        /** @var non-empty-string $code */
        return $this->totpFactory->createTotpForUser($user)->verify($code, null, $this->leeway ?? $this->window);
    }

    public function getQRContent(TwoFactorInterface $user): string
    {
        return $this->totpFactory->createTotpForUser($user)->getProvisioningUri();
    }

    public function generateSecret(): string
    {
        return Base32::encodeUpperUnpadded(random_bytes(32));
    }
}
