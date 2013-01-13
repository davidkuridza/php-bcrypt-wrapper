<?php
/**
 * PHP bcrypt wrapper
 *
 * Bcrypt is a wrapper to simplify the use of bcrypt algorithm in PHP.
 *
 * Functionality is stronlgy based on article published by Thomas Ptacek on
 * http://chargen.matasano.com/chargen/2007/9/7/enough-with-the-rainbow-tables-what-you-need-to-know
 * -about-s.html. It also features constant-time algorithm as nicely described by Coda Hale on
 * http://codahale.com/a-lesson-in-timing-attacks/.
 *
 * Usage example:
 *
 *   // hash password before storing it
 *   $hashed = Bcrypt::hash($password);
 *
 *   // check password by comparing it to its hashed value
 *   $check  = Bcrypt::check($password, $hashed);
 *
 *   // use a stronger salt
 *   $salt   = Bcrypt::salt(24); // 2^24 iterations
 *   $hashed = Bcrypt::hash($password, $salt);
 *
 * @author   David Kuridža <david@kuridza.si>
 * @license  http://www.opensource.org/licenses/mit-license.php MIT
 * @link     http://github.com/davidkuridza/php-bcrypt-wrapper
 */
class Bcrypt
{

    /**
     * Default number of iterations for salt generation. Can be between and including `4` and `31`.
     *
     * @var integer
     */
    const DEFAULT_ITERATION_COUNT = 10;

    /**
     * Hashes a password using PHP's `crypt()` function and a salt. If no salt is provided, it is
     * generated using `Bcrypt::salt()` with default iteration of `Bcrypt::DEFAULT_ITERATION_COUNT`.
     *
     * @param  string  $password  Password to be hashed.
     * @param  string  $salt      Optional. The salt string to be used.
     * @return string
     */
    public static function hash($password, $salt = null)
    {
        return crypt($password, $salt ? : self::salt());
    }

    /**
     * An alias for `Bcrypt::verify()`. Will be removed in v1.1.
     *
     * @param  string  $password  Password to check.
     * @param  string  $hash      Hashed password to compare `$password` to.
     * @return boolean
     * @see    Bcrypt::verify()
     * @deprecated since version 1.0.1
     */
    public static function check($password, $hash)
    {
        return self::verify($password, $hash);
    }

    /**
     * Checks `$password` and its stored `$hash` value using PHP's `crypt()` function and
     * constant-time algorithm to defend againt timing attacks, see
     * http://codahale.com/a-lesson-in-timing-attacks/ for more details.
     *
     * @param  string  $password  Password to check.
     * @param  string  $hash      Hashed password to compare `$password` to.
     * @return boolean
     */
    public static function verify($password, $hash)
    {
        // hash it
        $password = crypt($password, $hash);

        // firstly, make sure both hashes are of the same length
        if ( ($length = strlen($password)) !== strlen($hash) )
        {
            return false;
        }

        // flag to be returned
        $result = 0;
        // check each character
        for ( $i=0; $i<$length; $i++ )
        {
            // character at position $i need to be the same
            $result |= $password[$i] !== $hash[$i];
        }
        // so, is it valid?
        return $result === 0;
    }

    /**
     * Generate cryptographically strong salt using Blowfish method.
     *
     * @param  integer  $iteration  Optional. Base-2 logarithm of the iteration, defaults to `10`.
     *                                        Can be between and including `4` and `31`.
     * @return string
     * @throws \InvalidArgumentException if `$iterationCount` is out of bounds.
     */
    public static function salt($iterationCount = self::DEFAULT_ITERATION_COUNT)
    {
        // make sure $iteration is valid
        if ( (int)$iterationCount < 4 || (int)$iterationCount > 31 )
        {
            $message = '$iterationCount value has to be between 4 and 31.';
            throw new \InvalidArgumentException($message);
        }

        // see https://bugs.php.net/bug.php?id=55477 for more information on prefix based on PHP version
        return sprintf(
            '%s%02d$%s',
            0 <= version_compare(PHP_VERSION, '5.3.7') ? '$2y$' : '$2a$',
            $iterationCount,
            // black magic :)
            substr(
                strtr(
                    base64_encode(openssl_random_pseudo_bytes(16)), '+', '.'
                ), 0, 22
            )
        );
    }

}
