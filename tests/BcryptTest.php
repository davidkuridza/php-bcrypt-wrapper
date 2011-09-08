<?php

require_once __DIR__ . '/../src/Bcrypt.php';

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
        $salt2 = Bcrypt::salt(3);
        $salt3 = Bcrypt::salt(4);
        $salt4 = Bcrypt::salt(5);
        $salt5 = Bcrypt::salt(10);
        $salt6 = Bcrypt::salt(11);
        $salt7 = Bcrypt::salt(31);
        $salt8 = Bcrypt::salt(32);

        // lenght
        $this->assertEquals(29, strlen($salt1));
        $this->assertEquals(29, strlen($salt2));
        $this->assertEquals(29, strlen($salt3));
        $this->assertEquals(29, strlen($salt4));
        $this->assertEquals(29, strlen($salt5));
        $this->assertEquals(29, strlen($salt6));
        $this->assertEquals(29, strlen($salt7));
        $this->assertEquals(29, strlen($salt8));

        // check iteration
        $this->assertEquals('$2a$10$', substr($salt1, 0, 7));
        $this->assertEquals('$2a$10$', substr($salt2, 0, 7));
        $this->assertEquals('$2a$04$', substr($salt3, 0, 7));
        $this->assertEquals('$2a$05$', substr($salt4, 0, 7));
        $this->assertEquals('$2a$10$', substr($salt5, 0, 7));
        $this->assertEquals('$2a$11$', substr($salt6, 0, 7));
        $this->assertEquals('$2a$31$', substr($salt7, 0, 7));
        $this->assertEquals('$2a$10$', substr($salt8, 0, 7));
    }

}