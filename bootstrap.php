<?php

Autoloader::add_classes(array(
        'Auth\\Auth_Acl_MongoAcl'  => __DIR__.'/classes/auth/acl/mongoacl.php',
    
	'Auth\\Auth_Group_MongoGroup'  => __DIR__.'/classes/auth/group/mongogroup.php',
    
	'Auth\\Auth_Login_MongoAuth'      => __DIR__.'/classes/auth/login/mongoauth.php',
	'Auth\\MongoUserUpdateException'  => __DIR__.'/classes/auth/login/mongoauth.php',
	'Auth\\MongoUserWrongPassword'    => __DIR__.'/classes/auth/login/mongoauth.php',
));

?>
