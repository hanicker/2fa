<?php
namespace Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Email;

use Doctrine\ORM\EntityManager;
use Scheb\TwoFactorBundle\Mailer\AuthCodeMailerInterface;
use Scheb\TwoFactorBundle\Model\Email\TwoFactorInterface;

class AuthCodeManager
{

    /**
     *
     * @var \Doctrine\ORM\EntityManager $em
     */
    private $em;

    /**
     *
     * @var \Scheb\TwoFactorBundle\Mailer\AuthCodeMailerInterface $mailer
     */
    private $mailer;

    /**
     * Digit number of authentication code
     *
     * @var integer $digits
     */
    private $digits;

    /**
     * Construct the code generator service
     *
     * @param \Doctrine\ORM\EntityManager                           $em
     * @param \Scheb\TwoFactorBundle\Mailer\AuthCodeMailerInterface $mailer
     * @param integer                                               $digits
     */
    public function __construct(EntityManager $em, AuthCodeMailerInterface $mailer, $digits)
    {
        $this->em = $em;
        $this->mailer = $mailer;
        $this->digits = $digits;
    }

    /**
     * Generate a new authentication code an send it to the user
     *
     * @param \Scheb\TwoFactorBundle\Model\Email\TwoFactorInterface $user
     */
    public function generateAndSend(TwoFactorInterface $user)
    {
        $min = pow(10, $this->digits - 1);
        $max = pow(10, $this->digits) - 1;
        $code = $this->generateCode($min, $max);
        $user->setEmailAuthCode($code);
        $this->em->persist($user);
        $this->em->flush();
        $this->mailer->sendAuthCode($user);
    }

    /**
     * Validates the code, which was entered by the user
     *
     * @param  \Scheb\TwoFactorBundle\Model\Email\TwoFactorInterface $user
     * @param  integer                                               $code
     * @return bool
     */
    public function checkCode(TwoFactorInterface $user, $code)
    {
        return $user->getEmailAuthCode() == $code;
    }

    /**
     * Generate authentication code
     *
     * @param integer $min
     * @param integer $max
     * @return integer
     */
    protected function generateCode($min, $max)
    {
        return mt_rand($min, $max);
    }
}