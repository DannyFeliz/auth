<?php

namespace Baka\Auth\Models;

use Phalcon\Validation;
use Phalcon\Validation\Validator\Email;
use Phalcon\Validation\Validator\PresenceOf;
use Phalcon\Validation\Validator\Regex;
use Phalcon\Validation\Validator\Uniqueness;

class Users extends \Phalcon\Mvc\Model
{
    /**
     * @var integer
     */
    public $user_id;

    /**
     * @var string
     */
    public $email;

    /**
     * @var string
     */
    public $password;

    /**
     * @var string
     */
    public $firstname;

    /**
     * @var string
     */
    public $lastname;

    /**
     * @var string
     */
    public $displayname;

    /**
     * @var string
     */
    public $registered;

    /**
     * @var string
     */
    public $lastvisit;

    /**
     * @var string
     */
    public $dob;

    /**
     * @var string
     */
    public $sex;

    /**
     * @var string
     */
    public $timezone;

    /**
     * @var integer
     */
    public $city_id;

    /**
     * @var integer
     */
    public $state_id;

    /**
     * @var integer
     */
    public $country_id;

    /**
     * @var integer
     */
    public $welcome = 0;

    /**
     * @var string
     */
    public $profile_image;
    public $profile_image_mobile;

    /**
     * @var string
     */
    public $profile_remote_image;

    /**
     * @var int
     */
    public $user_active;

    /**
     * @var string
     */
    public $user_activation_key;

    /**
     * @var string
     */
    public $user_activation_email;

    public $loggedIn = false;

    public $location = '';

    public $interest = '';

    public $profile_privacy = 0;

    public $profile_image_thumb = ' ';

    public $user_activation_forgot = '';

    public $language;

    public $session_id = '';

    public $session_key = '';

    public $banned;

    /**
     *
     */
    public static $locale = 'ja_jp';

    /**
     *
     */
    public function initialize()
    {
        $this->hasOne('user_id', 'Baka\Auth\Models\Sessions', 'user_id', ['alias' => 'session']);
    }

    /**
     * Validations and business logic
     */
    public function validation()
    {
        $validator = new Validation();
        $validator->add(
            'email',
            new Email([
                'field' => 'email',
                'required' => true,
            ])
        );

        $validator->add(
            'displayname',
            new PresenceOf([
                'field' => 'displayname',
                'required' => true,
            ])
        );

        $validator->add(
            'displayname',
            new Regex([
                'field' => 'displayname',
                'message' => _('Please use alphanumerics only.'),
                'pattern' => '/^[A-Za-z0-9_-]{1,16}$/',
            ])
        );

        // Unique values
        $validator->add(
            'email',
            new Uniqueness([
                'field' => 'email',
                'message' => _('This email already has an account.'),
            ])
        );

        $validator->add(
            'displayname',
            new Uniqueness([
                'field' => 'displayname',
                'message' => _('The username is already taken.'),
            ])
        );

        return $this->validate($validator);
    }

    /**
     * get Id
     *
     * @return int
     */
    public function getId()
    {
        return $this->user_id;
    }

    /**
     * get the user by its Id, we can specify the cache if we want to
     * we only get result if the user is active
     *
     * @param int $userId
     * @param boolean $cache
     *
     * @return User
     */
    public static function getById($userId, $cache = false)
    {
        $options = null;
        $key = 'userInfo_' . $userId;

        if ($cache) {
            $options = ['cache' => ['lifetime' => 3600, 'key' => $key]];
        }

        if ($userData = Users::findFirstByUser_id($userId, $options)) {
            return $userData;
        } else {
            throw new \Exception(_('The specified user does not exist in our database.'));
        }
    }

    /**
     * is the user active?
     *
     * @return boolean
     */
    public function isActive()
    {
        return $this->user_active;
    }

    /**
     *  User login
     *
     * @param string $username
     * @param string $password
     * @param int $autologin
     * @param boolean $socialLogin , if this is true it means that your are login in from a social engine, so  we wont verify your password ? :S are we sure ???
     * @return users
     */
    public static function login($username, $password, $autologin = 1, $admin, $userIp)
    {
        //trim username
        $username = ltrim(trim($username));
        $password = ltrim(trim($password));

        //load config
        $config = new \stdClass();
        $config->login_reset_time = getenv('AUTH_MAX_AUTOLOGIN_TIME');
        $config->max_login_attempts = getenv('AUTH_MAX_AUTOLOGIN_ATTEMPS');

        //if its a email lets by it by email, if not by displayname
        $userInfo = !filter_var($username, FILTER_VALIDATE_EMAIL) ? self::findFirstByDisplayname($username) : self::findFirstByEmail($username);

        //first we find the user
        if ($userInfo) {
            // If the last login is more than x minutes ago, then reset the login tries/time
            if ($userInfo->user_last_login_try && $config->login_reset_time && $userInfo->user_last_login_try < (time() - ($config->login_reset_time * 60))) {
                $userInfo->user_login_tries = 0; //volvemos tu numero de logins a 0 y intentos
                $userInfo->user_last_login_try = 0;
                $userInfo->update();
            }

            // Check to see if user is allowed to login again... if his tries are exceeded
            if ($userInfo->user_last_login_try && $config->login_reset_time && $config->max_login_attempts && $userInfo->user_last_login_try >= (time() - ($config->login_reset_time * 60)) && $userInfo->user_login_tries >= $config->max_login_attempts) {
                throw new \Exception(sprintf(_('You have exhausted all login attempts.'), $config->max_login_attempts));
            }

            //will only work with php.5.5 new password api
            if (password_verify($password, trim($userInfo->password)) && $userInfo->user_active) {
                //rehas passw if needed
                $userInfo->passwordNeedRehash($password);

                $autologin = (isset($autologin)) ? true : 0;

                $admin = (isset($admin)) ? 1 : 0;

                $session = new \Baka\Auth\Models\Sessions();

                $userSession = $session->session_begin($userInfo->user_id, $userIp, getenv('PAGE_INDEX'), false, $autologin, $admin);

                // Reset login tries
                $userInfo->lastvisit = date('Y-m-d H:i:s'); //volvemos tu numero de logins a 0 y intentos
                $userInfo->user_login_tries = 0; //volvemos tu numero de logins a 0 y intentos
                $userInfo->user_last_login_try = 0;
                $userInfo->update();

                if ($userSession) {
                    //login correcto pasa al sistema
                    return $userSession;
                } else {
                    throw new \Exception(sprintf(_("Couldn't start session: %d %s."), __LINE__, __FILE__));
                }
            } // Only store a failed login attempt for an active user - inactive users can't login even with a correct password
            elseif ($userInfo->user_active) {
                // Save login tries and last login
                if ($userInfo->user_id != ANONYMOUS) {
                    $userInfo->user_login_tries += 1;
                    $userInfo->user_last_login_try = time();
                    $userInfo->update();
                }

                throw new \Exception(_('Wrong password, please try again.'));
            } else {
                throw new \Exception(_('User has not been activated, please check your email for the activation link.'));
            }
        } else {
            throw new \Exception(_('The specified user does not exist.'));
        }
    }

    /**
     *
     * user signup to the service
     * @return boolean
     */
    public function signUp()
    {
        //print_r($this); die();
        $this->sex = 'U';
        $this->firstname = ' ';
        $this->lastname = ' ';
        $this->dob = date('Y-m-d');
        $this->lastvisit = date('Y-m-d H:i:s');
        $this->registered = date('Y-m-d H:i:s');
        $this->password = self::passwordHash($this->password);
        $this->timezone = "America/New_York";
        $this->user_level = 3;
        $this->user_active = 0;
        $this->profile_header = ' ';
        $this->user_login_tries = 0;
        $this->user_last_login_try = 0;
        $this->session_time = time();
        $this->session_page = time();

        if (empty($this->language)) {
            $this->language = $this->usingSpanish() ? 'ES' : 'EN';
        }

        //hash de activacion para el correo
        //$crypt = new Phalcon\Crypt();
        $this->user_activation_key = $this->generateActivationKey(); //sha1(mt_rand(10000,99999).time().$this->email);  // sha1($this->displayname.time()."naruho.do_^^");

        if ($this->save()) {
            return true;
        }

        //fallo el registro
        return false;
    }

    /**
     * cget the social profile of a users, passing its socialnetwork
     *
     * @param string $site
     * @return Hybridauth\Entity\Profile
     */
    public static function getSocialProfile($site = 'facebook')
    {
        $config = \Phalcon\DI::getDefault()->getConfig()->social_config->toArray(); //dirname(dirname(dirname(__FILE__ ))) . "/config/social_config.php";
        $hybridauth = new \Hybridauth\Hybridauth($config);

        //$adapter = $hybridauth->authenticate( "Google" );
        $adapter = $hybridauth->authenticate($site);

        // request user profile
        return $adapter->getUserProfile();
    }

    /**
     * logout the user from its social network
     *
     * @param string $site
     * @return boolean
     */
    public static function disconnectSocialProfile($site = 'facebook')
    {
        $config = \Phalcon\DI::getDefault()->getConfig()->social_config->toArray(); //dirname(dirname(dirname(__FILE__ ))) . "/config/social_config.php";
        $hybridauth = new \Hybridauth\Hybridauth($config);
        return $hybridauth->logoutAllProviders();
        //$adapter = $hybridauth->authenticate( "Google" );
        $adapter = $hybridauth->authenticate($site);

        // request user profile
        return $adapter->logout();
    }

    /**
     * Has for the user password
     *
     * @param string
     *
     * @return string
     */
    public static function passwordHash($password)
    {
        //cant use it aas a object property cause php sucks and can call a function on a property with a array -_-
        $options = [
            //'salt' => mcrypt_create_iv(22, MCRYPT_DEV_URANDOM), // Never use a static salt or one that is not randomly generated.
            'cost' => 12, // the default cost is 10
        ];

        $hash = password_hash($password, PASSWORD_DEFAULT, $options);

        return $hash;
    }

    /**
     * Check if the user password needs to ve rehash
     * why? php shit with the new API http://www.php.net/manual/en/function.password-needs-rehash.php
     *
     * @param string $password
     * @return boolean
     */
    public function passwordNeedRehash($password)
    {
        $options = [
            //'salt' => mcrypt_create_iv(22, MCRYPT_DEV_URANDOM), // Never use a static salt or one that is not randomly generated.
            'cost' => 12, // the default cost is 10
        ];

        if (password_needs_rehash($this->password, PASSWORD_DEFAULT, $options)) {
            $this->password = self::passwordHash($password);
            $this->update();

            return true;
        }

        return false;
    }

    /**
     * get user by there email address
     * @return User
     */
    public static function getByEmail($email)
    {
        return self::findFirst(['email = :email:', 'bind' => ['email' => $email]]);
    }

    /**
     * get the user profileHeader
     *
     * @param boolean $mobile
     * @return string
     */
    public function getProfileHeader($mobile = false)
    {
        //$this->cdn
        $cdn = \Phalcon\DI::getDefault()->getCdn() . '/profile_headers/';
        $header = null;
        $image = !$mobile ? $this->profile_header : $this->profile_header_mobile;

        if (!empty($this->profile_header)) {
            $header = $cdn . $image;
        }

        return $header;
    }

    /**
     * get the user avatar
     * @return string
     */
    public function getAvatar()
    {
        //$this->cdn
        $cdn = \Phalcon\DI::getDefault()->getCdn() . '/avatars/';
        $avatar = $cdn . 'nopicture.png';

        if (!empty($this->profile_image)) {
            $avatar = $cdn . $this->profile_image;
        } elseif (!empty($this->profile_remote_image)) {
            $avatar = $this->profile_remote_image;
        }

        return $avatar;
    }

    /**
     * get user nickname
     * @return string
     */
    public function getDisplayName()
    {
        return strtolower($this->displayname);
    }

    /**
     * get user email
     * @return string
     */
    public function getEmail()
    {
        return $this->email;
    }

    /**
     * is the user logged in?
     * @return boolean
     */
    public function isLoggedIn()
    {
        return $this->loggedIn;
    }

    /**
     * is thie user admin level?
     * @return boolean
     */
    public function isAdmin()
    {
        return $this->user_level == 1 ? true : false;
    }

    /**
     * Determine if the user is a moderator
     *
     * @return boolean
     */
    public function isModerator()
    {
        return $this->isAdmin() ? true : false;
    }

    /**
     * Generate a user activation key
     * @return string
     */
    public function generateActivationKey()
    {
        return sha1(mt_rand(10000, 99999) . time() . $this->email);
    }

    /**
     * get the user sex, not get sex from the user :P
     *
     * @return string
     */
    public function getSex()
    {
        if ($this->sex == 'M') {
            return _('Male');
        } elseif ($this->sex == 'F') {
            return _('Female');
        } else {
            return _('Undefined');
        }
    }

    /**
     * Log a user out of the system
     *
     * @return boolean
     */
    public function logOut()
    {
        $session = new \Baka\Auth\Models\Sessions();
        $session->session_end($this);

        return true;
    }

    /**
     * Clean the user session from the system
     *
     * @return true
     */
    public function cleanSession()
    {
        $query = new \Phalcon\Mvc\Model\Query("DELETE FROM \Baka\Auth\Models\Sessions WHERE user_id = '{$this->user_id}'", $this->getDI());
        $query->execute();
        $query = new \Phalcon\Mvc\Model\Query("DELETE FROM  \Baka\Auth\Models\SessionKeys WHERE user_id = '{$this->user_id}'", $this->getDI());
        $query->execute();

        return true;
    }

    /**
     * Give the user a order array with the user configuration
     */
    public function getConfig()
    {
        $redis = $this->getDI()->getRedis();

        //get if from redis first
        if (!empty($redisConfig = $redis->hGetAll($this->getNotificationKey()))) {
            return $redisConfig;
        }

        $config = array();
        $userConfiguration = $this->getConfigs(['hydration' => \Phalcon\Mvc\Model\Resultset::HYDRATE_ARRAYS]);

        foreach ($userConfiguration as $value) {
            $config[$value['name']] = $value['value'];
        }

        return $config;
    }

    /**
     * get the user session id
     *
     * @return string
     */
    public function getSessionId()
    {
        //if its empty get it from the relationship, else get it from the property
        return empty($this->session_id) ? $this->getSession(['order' => 'time desc'])->session_id : $this->session_id;
    }

    /**
     * does the user as the configuration on?
     *
     * @param  $key string
     * @return boolean
     */
    public function hasConfig($key)
    {
        $redis = $this->getDI()->getRedis();
        $hashKey = $this->getNotificationKey(); //'user_notifications_'.$this->user_id;

        return $redis->hGet($hashKey, $key);
    }

    /**
     * get the user language
     *
     * @return string
     */
    public function getLanguage($short = false)
    {
        if ($this->isLoggedIn() && !empty($this->language)) {
            $lang = !$short ? strtolower($this->language) . '_' . $this->language : strtolower($this->language);
        } elseif ($this->getDI()->getSession()->has('requestLanguage')) {
            $lang = !$short ? $this->getDI()->getSession()->get('requestLanguage') . '_' . strtoupper($this->getDI()->getSession()->get('requestLanguage')) : strtolower($this->getDI()->getSession()->get('requestLanguage'));
        } else {
            if (array_key_exists('HTTP_ACCEPT_LANGUAGE', $_SERVER)) {
                $lang = !$short ? \Locale::acceptFromHttp($_SERVER['HTTP_ACCEPT_LANGUAGE']) : strtolower(\Locale::acceptFromHttp($_SERVER['HTTP_ACCEPT_LANGUAGE']));
            } else {
                $lang = null;
            }
        }

        return $lang;
    }

    /**
     * Get the language user prefix
     *
     * @return string
     */
    public function getLanguageUrl()
    {
        if (strtolower($this->getLanguage()) == 'es_es') {
            return '/es';
        }

        return null;
    }

    /**
     * Is the user using the spanish langugue?
     *
     * @return [type] [description]
     */
    public function usingSpanish()
    {
        if (strtolower($this->getLanguage()) == 'es_es') {
            return true;
        }

        return false;
    }
}
