<?php

declare(strict_types=1);

namespace Scheb\TwoFactorBundle\Security\TwoFactor\Event;

use Scheb\TwoFactorBundle\Security\Authentication\Token\TwoFactorTokenInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\TwoFactorFirewallConfig;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * @final
 */
class TwoFactorFormListener implements EventSubscriberInterface
{
    private TwoFactorFirewallConfig $twoFactorFirewallConfig;
    private TokenStorageInterface $tokenStorage;
    private EventDispatcherInterface $eventDispatcher;

    public function __construct(
         TwoFactorFirewallConfig $twoFactorFirewallConfig,
         TokenStorageInterface $tokenStorage,
         EventDispatcherInterface $eventDispatcher
    ) {
        $this->twoFactorFirewallConfig = $twoFactorFirewallConfig;
        $this->tokenStorage = $tokenStorage;
        $this->eventDispatcher = $eventDispatcher;
    }

    public function onKernelRequest(RequestEvent $requestEvent): void
    {
        $request = $requestEvent->getRequest();
        if (!$request->hasSession()) {
            return;
        }

        if (!$this->twoFactorFirewallConfig->isAuthFormRequest($request)) {
            return;
        }

        $token = $this->tokenStorage->getToken();
        if (!($token instanceof TwoFactorTokenInterface)) {
            return;
        }

        $event = new TwoFactorAuthenticationEvent($request, $token);
        $this->eventDispatcher->dispatch($event, TwoFactorAuthenticationEvents::FORM);
    }

    /**
     * {@inheritdoc}
     */
    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::REQUEST => 'onKernelRequest'];
    }
}
