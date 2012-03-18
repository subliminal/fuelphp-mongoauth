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

namespace Auth;


class MongoUserUpdateException extends \FuelException {}

class MongoUserWrongPassword extends \FuelException {}

/**
 * MongoAuth login driver
 */
class Auth_Login_MongoAuth extends \Auth\Auth_Login_Driver
{

    public static function _init()
    {
            \Config::load('mongoauth', true);
    }
    // Implement all the needed functions and variables defined in the driver class.
    
    /**
        * @var  Database_Result  when login succeeded
        */
    protected $user = null;

    /**
        * @var  array  value for guest login
        */
    protected static $guest_login = array(
            'id' => 0,
            'username' => 'guest',
            'group' => '0',
            'login_hash' => false,
            'email' => false
    );

    /**
        * @var array MongoAuth class config
        */
    protected $config = array(
            'drivers' => array('group' => array('MongoGroup')),
            //'additional_fields' => array('profile_fields'),
    );
    
	/**
	 * Check for login
	 *
	 * @return  bool
	 */
	protected function perform_check()
	{
		$email    = \Session::get('email');
		$login_hash  = \Session::get('login_hash');

		// only worth checking if there's both a username and login-hash
		if ( ! empty($email) and ! empty($login_hash))
		{

                    
			if (is_null($this->user) or ($this->user['email'] != $email and $this->user != static::$guest_login))
			{
				$this->user = \Mongo_Db::instance(\Config::get('mongoauth.db_config'))
					->where(
                                                array(
                                                    'email' => $email
                                                ))
                                        ->get_one(\Config::get('mongoauth.collection'));
                                
                                print_r($this->user);
			}                 

			// return true when login was verified
			if ($this->user and $this->user['login_hash'] === $login_hash)
			{
				return true;
			}
		}

		// no valid login when still here, ensure empty session and optionally set guest_login
		$this->user = \Config::get('mongoauth.guest_login', true) ? static::$guest_login : false;
		\Session::delete('email');
		\Session::delete('login_hash');

		return false;
	}
        /**
         * Generate salt
         * 
         * Generates a 16 byte salt user specific salt
         *  
         */
        public function generate_salt() 
        {
            $salt = "";

            while(strlen($salt) < 16) {

                $salt = $salt . uniqid(uniqid(mt_rand(1000,9999),true), true);
            }

            $i = 0;
            $salt2 = "";

            while($i < 16) 
            {
                $salt2 = $salt2 . $salt[$i];
                $i++;
            }

            return $salt2;
        }
        
        /**
         * Generate hash
         * 
         * This overrides the default method (but still uses it). Effectively, it double hashes
         *  
         * @param string
         * @param string
         */
        public function mongo_hash_password($password, $salt) 
        {
            $encrypted_pass = \Crypt::encode($password, $salt);
            
            return (parent::hash_password($encrypted_pass));
        }
        
        
	/**
	 * Login user
	 *
	 * @param   string
	 * @param   string
	 * @return  bool
	 */
	public function login($email = '', $password = '')
	{

            
            $email = trim($email) ?: trim(\Input::post(\Config::get('mongoauth.email_post_key', 'email')));
            $password = trim($password) ?: trim(\Input::post(\Config::get('mongoauth.password_post_key', 'password')));
            

            if (empty($email) or empty($password))
            {
                    return false;
            }

            $this->user = \Mongo_Db::instance(\Config::get('mongoauth.db_config'))
                    ->where(array(
                        'email' => $email
                    ))
                    ->get_one(\Config::get('mongoauth.collection'));
            

            
            if (is_array($this->user) && isset($this->user['salt']) && isset($this->user['password']))
            {
                $password = $this->mongo_hash_password($password, $this->user['salt']);
                
                if ($password != $this->user['password']) {
                    return false;
                }
            } 
            else 
            {
                $this->user = \Config::get('mongoauth.guest_login', true) ? static::$guest_login : false;
                \Session::delete('email');
                \Session::delete('login_hash');
                return false;
            }

            \Session::set('email', $this->user['email']);
            \Session::set('login_hash', $this->create_login_hash());
            \Session::instance()->rotate();
            return true;
	}
        
	/**
	 * Force login user
	 *
	 * @param   string
	 * @return  bool
	 */
	public function force_login($user_id = '')
	{
		if (empty($user_id))
		{
			return false;
		}

		$this->user = \Mongo_Db::instance(\Config::get('mongoauth.db_config'))
			->where(
                                array(
                                    '$id' => $user_id
                                ))
			->get_one(\Config::get('mongoauth.collection'));

		if ($this->user == false)
		{
			$this->user = \Config::get('mongoauth.guest_login', true) ? static::$guest_login : false;
			\Session::delete('email');
			\Session::delete('login_hash');
			return false;
		}

		\Session::set('email', $this->user['email']);
		\Session::set('login_hash', $this->create_login_hash());
		return true;
	}
        
	/**
	 * Logout user
	 *
	 * @return  bool
	 */
	public function logout()
	{
		$this->user = \Config::get('mongoauth.guest_login', true) ? static::$guest_login : false;
		\Session::delete('email');
		\Session::delete('login_hash');
		return true;
	}
        
	/**
	 * Create new user
	 *
	 * @param   array   array of fields to add to db
	 * @param   int     group id
	 */
	public function create_user($fields, $group = 1)
	{
		if (empty($fields) or empty($fields['email']) or empty($fields['password']))
		{
			throw new \MongoUserUpdateException('Email and password can\'t be empty.');
		}
                
		$password = trim($fields['password']);
		$email = filter_var(trim($fields['email']), FILTER_VALIDATE_EMAIL);
                
                unset($fields['email']);
                unset($fields['password']);

		$same_users = \Mongo_Db::instance(\Config::get('mongoauth.db_config'))
			->where(array(
                            'email' => $email
                        ))
			->get(\Config::get('mongoauth.collection'));
               
		if (count($same_users) > 0)
		{
                    throw new \MongoUserUpdateException('Email address already exists');
		}
                
                $fields['salt'] = $this->generate_salt();
                
		$user = array(
			'email'           => $email,
			'password'        => $this->mongo_hash_password((string) $password, $fields['salt']),
			'group'           => (int) $group,
			'created_at'      => \Date::forge()->get_timestamp()
		);
                
                if (!empty($fields)) {
                    $user += $fields;
                }
                
		$result = \Mongo_Db::instance(\Config::get('mongoauth.db_config'))
			->insert(\Config::get('mongoauth.collection'), $user);
                
		return ($result->{'$id'} ? $result->{'$id'} : false);
	}
        
/**
	 * Update a user's properties
	 * Note: Username cannot be updated, to update password the old password must be passed as old_password
	 *
	 * @param   Array  properties to be updated including profile fields
	 * @param   string
	 * @return  bool
	 */
	public function update_user($values, $email = null)
	{
		$email = $email ?: $this->user['email'];
                
                $email = filter_var(trim($values['email']), FILTER_VALIDATE_EMAIL);
                
                if ( ! $email)
                {
                        throw new \MongoUserUpdateException('Email address is not valid');
                }
                
		$current_values = \Mongo_Db::instance(\Config::get('mongoauth.db_config'))
			->where(
                                array(
                                    'email' => $email
                                ))
			->get_one('mongoauth.collection');
                        
		if (empty($current_values))
		{
			throw new \MongoUserUpdateException('Email not found');
		}

		$update = array();
		if (array_key_exists('email', $values))
		{
			throw new \MongoUserUpdateException('Email already exists.');
		}
		if (array_key_exists('password', $values))
		{
			if (empty($values['old_password'])
				or $current_values['password'] != $this->hash_password(trim($values['old_password']), $current_values['salt']))
			{
				throw new \MongoUserWrongPassword('Old password is invalid');
			}

			$password = trim(strval($values['password']));
			if ($password === '')
			{
				throw new \MongoUserUpdateException('Password can\'t be empty.');
			}
                        $update['salt'] = $this->generate_salt();
			$update['password'] = $this->mongo_hash_password($password, $update['salt']);
			unset($values['password']);
		}
                
		if (array_key_exists('old_password', $values))
		{
			unset($values['old_password']);
		}
                
		if (array_key_exists('group', $values))
		{
			if (is_numeric($values['group']))
			{
				$update['group'] = (int) $values['group'];
			}
			unset($values['group']);
		}
		if ( ! empty($values))
		{
			//$profile_fields = @unserialize($current_values->get('profile_fields')) ?: array();
                        $additional_fields = $current_files['values'] ?: array();
                        
			foreach ($values as $key => $val)
			{
				if ($val === null)
				{
                                        // unset isn't going to work with mongo, so we delete the record
					$additional_fields[$key] = '';
				}
				else
				{
					$additional_fields[$key] = $val;
				}
			}
			$update += $additional_fields;
		}

		$success = \Mongo_Db::instance(\Config::get('mongoauth.db_config'))
			->where(
                                array(
                                    'email' => $email
                                ))
			->update('mongoauth.collection', $update);

		// Refresh user
		if ($this->user['email'] == $email)
		{
			$this->user = \Mongo_Db::instance(\Config::get('mongoauth.db_config'))
				->where(
                                        array(
                                            'email' => $email
                                        ))
				->get_one('mongoauth.collection');
		}

		return $success;
	}
        
	/**
	 * Change a user's password
	 *
	 * @param   string
	 * @param   string
	 * @param   string  username or null for current user
	 * @return  bool
	 */
	public function change_password($old_password, $new_password, $email = null)
	{
		try
		{
			return (bool) $this->update_user(array('old_password' => $old_password, 'password' => $new_password), $email);
		}
		// Only catch the wrong password exception
		catch (MongoUserWrongPassword $e)
		{
			return false;
		}
	}
        
	/**
	 * Generates new random password, sets it for the given username and returns the new password.
	 * To be used for resetting a user's forgotten password, should be emailed afterwards.
	 *
	 * @param   string  $username
	 * @return  string
	 */
	public function reset_password($email)
	{
                $user['salt'] = $this->generate_salt();
                
		$new_password = \Str::random('alnum', 8);
		$user['password'] = $this->mongo_hash_password($new_password, $user['salt']);

		$update = \Mongo_Db::instance(\Config::get('mongoauth.db_config'))
			->where(
                            array(
                                'email' => $email
                            )
                        )
                        ->update(\Config::get('mongoauth.collection'), $user);
			

		if ( ! $update)
		{
			throw new \MongoUserUpdateException('Failed to reset password, user was invalid.');
		}

		return $user['password'];
	}
        
	/**
	 * Deletes a given user
	 *
	 * @param   string
	 * @return  bool|object
	 */
	public function delete_user($email)
	{
		if (empty($email))
		{
			throw new \MongoUserUpdateException('Cannot delete user with empty email');
		}

		$success = \DB::delete(\Config::get('simpleauth.table_name'))
			->where(
                            array(
                                'email' => $email
                            )
                        )
                        ->delete(\Config::get('mongoauth.collection'));

		return $success;
	}

	/**
	 * Creates a temporary hash that will validate the current login
	 *
	 * @return  string
	 */
	public function create_login_hash()
	{
		if (empty($this->user))
		{
			throw new \MongoUserUpdateException('User not logged in, can\'t create login hash.');
		}

		$last_login = \Date::forge()->get_timestamp();
		$login_hash = sha1(\Config::get('mongoauth.login_hash_salt').$this->user['email'].$last_login);

		\Mongo_Db::instance(\Config::get('mongoauth.db_config'))
                        ->where(array(
                            'email' => $this->user['email']
                        ))
			->update(\Config::get('mongoauth.collection'), 
                                array(
                                    'last_login' => $last_login, 
                                    'login_hash' => $login_hash
                                )
                            );

		$this->user['login_hash'] = $login_hash;

		return $login_hash;
	}

	/**
	 * Get the user's ID
	 *
	 * @return  Array  containing this driver's ID & the user's ID
	 */
	public function get_user_id()
	{
		if (empty($this->user))
		{
			return false;
		}

		return array($this->id, (int) $this->user['_id']->{'$id'});
	}

	/**
	 * Get the user's groups
	 *
	 * @return  Array  containing the group driver ID & the user's group ID
	 */
	public function get_groups()
	{
		if (empty($this->user))
		{
			return false;
		}

		return array(array('MongoGroup', $this->user['group']));
	}

	/**
	 * Get the user's emailaddress
	 *
	 * @return  string
	 */
	public function get_email()
	{
		if (empty($this->user))
		{
			return false;
		}

		return $this->user['email'];
	}

	/**
	 * There is no screen name, so get_screen_name doesn't return anything
	 *
	 * @return  string
	 */
	public function get_screen_name()
	{
		return null;
	}

	/**
	 * Extension of base driver method to default to user group instead of user id
	 */
	public function has_access($condition, $driver = null, $user = null)
	{
		if (is_null($user))
		{
			$groups = $this->get_groups();
			$user = reset($groups);
		}
		return parent::has_access($condition, $driver, $user);
	}

	/**
	 * Extension of base driver because this supports a guest login when switched on
	 */
	public function guest_login()
	{
		return \Config::get('simpleauth.guest_login', true);
	}
}
?>
