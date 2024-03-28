<?php

declare(strict_types=1);

namespace Scheb\TwoFactorBundle\Tests;

use DirectoryIterator;
use Traversable;
use function array_diff;
use function array_keys;
use function array_unique;
use function file_get_contents;
use function implode;
use function json_decode;
use function sprintf;


if(!function_exists('str_starts_with')){
    function str_starts_with(string $haystack, string $needle): bool
    {
        return strncmp($haystack, $needle, strlen($needle)) === 0;
    }
}


class ComposerJsonTest extends TestCase
{
    private const SRC_DIR = __DIR__.'/../src';

    /**
     * @test
     */
    public function packageDependenciesEqualRootDependencies(): void
    {
        $usedDependencies = ['symfony/symfony']; // Some builds add this to composer.json
        $rootDependencies = $this->getComposerDependencies(__DIR__.'/../composer.json');

        foreach ($this->listSubPackages() as $package) {
            $packageDependencies = $this->getComposerDependencies(self::SRC_DIR.'/'.$package.'/composer.json');
            foreach ($packageDependencies as $dependency => $version) {
                // Skip scheb/2fa-* dependencies
                if (str_starts_with($dependency, 'scheb/2fa-')) {
                    continue;
                }

                $message = sprintf('Dependency "%s" from package "%s" is not defined in root composer.json', $dependency, $package);
                $this->assertArrayHasKey($dependency, $rootDependencies, $message);

                $message = sprintf('Dependency "%s:%s" from package "%s" requires a different version in the root composer.json', $dependency, $version, $package);
                $this->assertEquals($version, $rootDependencies[$dependency], $message);

                $usedDependencies[] = $dependency;
            }
        }

        $unusedDependencies = array_diff(array_keys($rootDependencies), array_unique($usedDependencies));
        $message = sprintf('Dependencies declared in root composer.json, which are not declared in any sub-package: %s', implode($unusedDependencies));
        $this->assertCount(0, $unusedDependencies, $message);
    }

    /**
     * @test
     */
    public function rootDependenciesContainedInAppDependencies(): void
    {
        $rootDependencies = $this->getComposerDependencies(__DIR__.'/../composer.json');
        $appDependencies = $this->getComposerDependencies(__DIR__.'/../app/composer.json');

        foreach ($rootDependencies as $dependency => $version) {
            // Skip symfony/* dependencies as they're replaced by symfony/symfony
            if (str_starts_with($dependency, 'symfony/')) {
                continue;
            }

            $message = sprintf('Dependency "%s" from root is not defined in app/composer.json', $dependency);
            $this->assertArrayHasKey($dependency, $appDependencies, $message);

            $message = sprintf('Dependency "%s:%s" from root is required in a different version in app/composer.json', $dependency, $version);
            $this->assertEquals($version, $appDependencies[$dependency], $message);
        }
    }

    /**
     * @test
     */
    public function rootReplacesSubPackages(): void
    {
        $rootReplaces = $this->getComposerReplaces(__DIR__.'/../composer.json');
        foreach ($this->listSubPackages() as $package) {
            $packageName = $this->getComposerPackageName(self::SRC_DIR.'/'.$package.'/composer.json');
            $message = sprintf('Root composer.json must replace the sub-packages "%s"', $packageName);
            $this->assertArrayHasKey($packageName, $rootReplaces, $message);
        }
    }

    /**
     * @return Traversable<string>
     */
    private function listSubPackages(): Traversable
    {
        foreach (new DirectoryIterator(self::SRC_DIR) as $dirInfo) {
            if (!$dirInfo->isDir() || $dirInfo->isDot()) {
                continue;
            }

            yield $dirInfo->getFilename();
        }
    }

    /**
     * @return array<string,string>
     */
    private function getComposerDependencies(string $composerFilePath): array
    {
        return $this->parseComposerFile($composerFilePath)['require'];
    }

    private function getComposerPackageName(string $composerFilePath): string
    {
        return $this->parseComposerFile($composerFilePath)['name'];
    }

    /**
     * @return array<string,string>
     */
    private function getComposerReplaces(string $composerFilePath): array
    {
        return $this->parseComposerFile($composerFilePath)['replace'];
    }

    /**
     * @return array<string,mixed>
     */
    private function parseComposerFile(string $composerFilePath): array
    {
        return json_decode(file_get_contents($composerFilePath), true);
    }
}
