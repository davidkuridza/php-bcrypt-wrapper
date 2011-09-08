<?php

class EnvTest extends \PHPUnit_Framework_TestCase
{

    /**
     * Check that all needed extensions are loaded.
     *
     * @return void
     */
    public function testDependencies()
    {
        // php 5.3+
        $this->assertFalse(version_compare(PHP_VERSION, '5.3') < 0);

        // openssl extension
        $this->assertTrue(extension_loaded('openssl'), 'Needed extension "openssl" NOT loaded.');
        $this->assertTrue(
            is_callable('openssl_random_pseudo_bytes'),
            '"openssl_random_pseudo_bytes() is not callable.'
        );

        // blowfish hash type
        $this->assertEquals(1, CRYPT_BLOWFISH, '"Blowfish" hash type is unavailable.');
    }

}