<?php

declare(strict_types=1);

namespace Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Google;

use OTPHP\TOTP;
use OTPHP\TOTPInterface;
use Scheb\TwoFactorBundle\Model\Google\TwoFactorInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Exception\TwoFactorProviderLogicException;
use function strlen;

/**
 * @final
 */
class GoogleTotpFactory
{
    /**
     * @var mixed
     */
    private $server;
    /**
     * @var mixed
     */
    private $issuer;
    /**
     * @var mixed
     */
    private $digits;

    public function __construct(
        $server,
        $issuer,
        $digits
    ) {
        $this->server = $server;
        $this->issuer = $issuer;
        $this->digits = $digits;
    }

    public function createTotpForUser(TwoFactorInterface $user): TOTPInterface
    {
        $secret = $user->getGoogleAuthenticatorSecret();
        if (null === $secret || 0 === strlen($secret)) {
            throw new TwoFactorProviderLogicException('Cannot initialize TOTP, no secret code provided.');
        }

        /** @psalm-suppress ArgumentTypeCoercion */
        $totp = TOTP::create($secret, 30, 'sha1', $this->digits);

        $userAndHost = $user->getGoogleAuthenticatorUsername().($this->server ? '@'.$this->server : '');
        $totp->setLabel($userAndHost);

        if ($this->issuer) {
            $totp->setIssuer($this->issuer);
        }

        return $totp;
    }
}
