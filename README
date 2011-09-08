PHP bcrypt wrapper
=======

PHP bcrypt is a wrapper to simplify the use of bcrypt algorithm in PHP.


Requirements
------------

* PHP 5.3 (or later)
* [OpenSSL](http://www.php.net/manual/en/openssl.requirements.php)
* [PHPUnit](https://github.com/sebastianbergmann/phpunit/) - Optional.


Installation
------------

Copy `src/Bcrypt.php` to location on the file system where needed.

To test whether `Bcrypt` works in your environment, you can simply run a PHPUnit test:

    $ cd tests
    $ phpunit


Usage
-------------

    include 'Bcrypt.php';

    // hash password before storing it
    $hashed = Bcrypt::hash($password);

    // check password by comparing it to its hashed value
    $check  = Bcrypt::check($password, $hashed);

    // use a stronger salt
    $salt   = Bcrypt::salt(24); // 2^24 iterations
    $hashed = Bcrypt::hash($password, $salt);


Contact
---------------------------------

Feel free to contact me via david@kuridza.si or [twitter](http://twitter.com/davidkuridza).