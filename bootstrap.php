<?php
/**
 * MongoAuth is a port (with modifications) of the SimpleAuth library included with FuelPHP
 *
 * @package    MongoAuth
 * @version    1.0
 * @author     Justin Hall
 * @license    MIT License
 * @copyright  2010 - 2011 Justin Hall
 */

/**
 * Fuel is a fast, lightweight, community driven PHP5 framework.
 *
 * @package    Fuel
 * @version    1.0
 * @author     Fuel Development Team
 * @license    MIT License
 * @copyright  2010 - 2011 Fuel Development Team
 * @link       http://fuelphp.com
 */

Autoloader::add_classes(array(
        'Auth\\Auth_Acl_MongoAcl'  => __DIR__.'/classes/auth/acl/mongoacl.php',
    
	'Auth\\Auth_Group_MongoGroup'  => __DIR__.'/classes/auth/group/mongogroup.php',
    
	'Auth\\Auth_Login_MongoAuth'      => __DIR__.'/classes/auth/login/mongoauth.php',
	'Auth\\MongoUserUpdateException'  => __DIR__.'/classes/auth/login/mongoauth.php',
	'Auth\\MongoUserWrongPassword'    => __DIR__.'/classes/auth/login/mongoauth.php',
));

?>
