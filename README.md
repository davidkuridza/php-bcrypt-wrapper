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

Copy `Bcrypt/Bcrypt.php` to location on the file system where needed.

To test whether `Bcrypt` works in your environment, you can simply run PHPUnit tests from root
directory:

    $ phpunit

An `Ant` build script is provided to simplify setting up the environment in case you would like to
contribute. Following targets are available:

    $ ant
    Buildfile: build.xml

    help:
         [echo] Usage: ant [target [target1 [target2] ...]]
         [echo] Targets:
         [echo]   help            print this message
         [echo]   build           setup env
         [echo]   clean           clean up and create artifact directories
         [echo]   tests           run unit tests

`$ ant build` will run `clean` and `tests`.


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

Feel free to contact me via [email](david@kuridza.si) or [twitter](http://twitter.com/davidkuridza).