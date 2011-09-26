<?php

require_once __DIR__ . '/../Bcrypt/Bcrypt.php';

class BcryptTest extends \PHPUnit_Framework_TestCase
{

    /**
     * Check behaviour of `Bcrypt::hash()`.
     *
     * @return void
     */
    public function testHash()
    {
        $hash1 = Bcrypt::hash('test123');
        $hash2 = Bcrypt::hash('password123');

        // length
        $this->assertEquals(60, strlen($hash1));
        $this->assertEquals(60, strlen($hash2));

        // Blowfish?
        $this->assertEquals('$2a$',    substr($hash1, 0, 4));
        $this->assertEquals('$2a$',    substr($hash2, 0, 4));
        $this->assertEquals('$2a$10$', substr($hash1, 0, 7));
        $this->assertEquals('$2a$10$', substr($hash2, 0, 7));

        // different salt
        $salt1 = Bcrypt::salt(5);
        $salt2 = Bcrypt::salt(11);

        $this->assertEquals('$2a$05$', substr(Bcrypt::hash('test123', $salt1), 0, 7));
        $this->assertEquals('$2a$11$', substr(Bcrypt::hash('test123', $salt2), 0, 7));
    }

    /**
     * Check behaviour of `Bcrypt::check()`.
     *
     * @return void
     */
    public function testCheck()
    {
        // hashes used for one time only, well, two times :)
        $hash1 = Bcrypt::hash('test123');
        $hash2 = Bcrypt::hash('password123');

        // test using already generated hashes
        $this->assertTrue(Bcrypt::check('test123',      $hash1));
        $this->assertTrue(Bcrypt::check('password123',  $hash2));
        $this->assertFalse(Bcrypt::check('test123',     $hash2));
        $this->assertFalse(Bcrypt::check('password123', $hash1));

        // generate new hash each time
        $this->assertTrue(Bcrypt::check('test123',      Bcrypt::hash('test123')));
        $this->assertTrue(Bcrypt::check('password123',  Bcrypt::hash('password123')));
        $this->assertFalse(Bcrypt::check('test123',     Bcrypt::hash('password123')));
        $this->assertFalse(Bcrypt::check('password123', Bcrypt::hash('test123')));

        // what happens if the hash is wrong?
        $this->assertFalse(Bcrypt::check('test123',     'WrongHash'));
        $this->assertFalse(Bcrypt::check('password123', 'AnotherWrongHash'));
    }

    /**
     * Check behaviour of `Bcrypt::salt()`.
     *
     * @return void
     */
    public function testSalt()
    {
        // hashes used for one time only, well, two times :)
        $salt1 = Bcrypt::salt();
        $salt2 = Bcrypt::salt(4);
        $salt3 = Bcrypt::salt(5);
        $salt4 = Bcrypt::salt(10);
        $salt5 = Bcrypt::salt(11);
        $salt6 = Bcrypt::salt(31);

        // lenght
        $this->assertEquals(29, strlen($salt1));
        $this->assertEquals(29, strlen($salt2));
        $this->assertEquals(29, strlen($salt3));
        $this->assertEquals(29, strlen($salt4));
        $this->assertEquals(29, strlen($salt5));
        $this->assertEquals(29, strlen($salt6));

        // anonymous helper function
        $sub = function($salt)
        {
            return substr($salt, 0, 7);
        };

        // check iteration
        $this->assertEquals(sprintf('$2a$%02d$', Bcrypt::DEFAULT_ITERATION_COUNT), $sub($salt1));
        $this->assertEquals('$2a$04$', $sub($salt2));
        $this->assertEquals('$2a$05$', $sub($salt3));
        $this->assertEquals('$2a$10$', $sub($salt4));
        $this->assertEquals('$2a$11$', $sub($salt5));
        $this->assertEquals('$2a$31$', $sub($salt6));

        // test invalid iteration count
        foreach ( array(0, 3, 32, 1337) as $i )
        {
            try
            {
                Bcrypt::salt($i);
                $message = 'InvalidArgumentException should have been thrown for $i = ' . $i;
                $this->fail($message);
            }
            catch ( InvalidArgumentException $e )
            {
            }
            // free it
            $i = null; unset($i);
        }
    }

}