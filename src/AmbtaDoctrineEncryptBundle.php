<?php

namespace Ambta\DoctrineEncryptBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;
use Ambta\DoctrineEncryptBundle\DependencyInjection\DoctrineEncryptExtension;

class AmbtaDoctrineEncryptBundle extends Bundle
{
    public function getContainerExtension()
    {
        return new DoctrineEncryptExtension();
    }
}
