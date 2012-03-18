MongoAuth
=========

MongoAuth is a SimpleAuth replacement for FuelPHP, which uses Mongo as
the database backend. For the most part, the package is a drop-in 
replacement for SimpleAuth with few cavets:

* Usernames (screen names) have been removed. The library uses
email address as the unique identifier for a user.
* Password hashing has been made (arguably) more secure. The system generates
a salt for the users password. It then re-hashes the password using the 
salt/secret exactly as SimpleAuth does. This effectively means evil people 
would need each users encoded password, their individual salt AND the 
applications secret key in order to get the plain-text password.
* The driver does NOT serialize additional data. SimpleAuth takes all 
additional fields and serielizes them into a "profile" field. It's good for 
a demo, but not particularly useful in real life. 

License
-------

Just like FuelPHP, this package is released under the MIT license.

Installation
------------

MongoAuth is released as a FuelPHP package, so installation is the same as 
any other package:

1. Download the package (or clone it) into APP/packages/mongoauth
2. Update your APP/fuel/config/auth.php file to:
	
	```php
	array (
		'driver' => array('MongoAuth'),
	);
	```

3. Upload your APP/fuel/config/config.php file and add mongoauth to your 
always_load. Note you must add auth first, as it's required for MongoAuth 
to work.

	```php
	'packages' => array(
		'auth',
		'mongoauth'
	);
	```

Warning
-------

This is still VERY much in Beta. I haven't even tested all of the methods yet, 
let alone get to UnitTesting. Don't use this in production but PLEASE use 
it in development, and let me know if there are issues (or, PR if you are
awesome).
