<?php
/**
 * DokuWiki Plugin authmantis (Auth Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Ventzy <v.kunev@gmail.com>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

class auth_plugin_authmantis extends DokuWiki_Auth_Plugin {


    /**
     * Constructor.
     */
    public function __construct() {
        parent::__construct(); // for compatibility

        $this->cando['external'] = true;
        $this->cando['logoff' ] = true;
        
        $this->success = true;
    }


    /**
     * Log off the current user [ OPTIONAL ]
     */
    public function logOff() {
      auth_logout();
    }

    /**
     * Do all authentication [ OPTIONAL ]
     *
     * @param   string  $user    Username
     * @param   string  $pass    Cleartext Password
     * @param   bool    $sticky  Cookie should not expire
     * @return  bool             true on successful auth
     */
    public function trustExternal($user, $pass, $sticky = false) {
        global $USERINFO;
        global $conf;
 
        $ValidUser = false;
 
        // Manage HTTP authentication with Negotiate protocol enabled
        $user = auth_prepare_username($user);
	$pass = auth_prepare_password($pass);
        // This is necessary in all cases where Authorization HTTP header is always set
	if(auth_is_user_authenticated())
	{
	    $user='';
	}
 
        // Has a user name been provided?
        if ( !empty ( $user ) )
        {   
            // User name provided, so login via form in progress...
            // Are the specified user name and password valid?
            if ( auth_attempt_login ( $user, $pass, $sticky ) )
            {   
                // Credential accepted...
                $_SERVER['REMOTE_USER'] = $user; // Set the user name (makes things work...)
                $ValidUser = true; // Report success.
            }
            else
            {   
                // Invalid credentials              
                        if ( !$silent )
                {   
                    msg ( $lang [ 'badlogin' ], -1 );
                }
                
                $ValidUser = false;
            }
        }
        else
        {   
            // No user name provided.
            // Is a user already logged in?
            if ( auth_is_user_authenticated ( ) )
            {   
                // Yes, a user is logged in, so set the globals...
                // is it a media display or a page?
                if (isset($_REQUEST['media'])) {
                    //media
                    $t_project_name = explode( ':', getNS( getID("media",false) ) );
                } else {
                    // normal page
                    $t_project_name = explode( ':', getNS( getID() ) );
                }
                $t_project_id = project_get_id_by_name( $t_project_name[1] );
                $t_access_level = access_get_project_level( $t_project_id );
                $t_access_level_string = strtoupper( MantisEnum::getLabel( config_get( 'access_levels_enum_string' ),  $t_access_level ) ); // mantis 1.2.0rc
                // $t_access_level_string = strtoupper( get_enum_to_string( config_get( 'access_levels_enum_string' ),  $t_access_level ) ); 
                $t_access_level_string_ex = strtoupper( $t_project_name[1] ) . '_' . $t_access_level_string;
 
                $USERINFO['grps'] = array( $t_access_level_string, $t_access_level_string_ex );
                $USERINFO[ 'pass' ] = current_user_get_field ( 'password' );
                $USERINFO[ 'name' ] = current_user_get_field ( 'username' );
                $USERINFO[ 'mail' ] = current_user_get_field ( 'email' );
                
                $_SERVER[ 'REMOTE_USER' ] = $USERINFO[ 'name' ];
                $_SESSION[ $conf[ 'title' ]][ 'auth' ][ 'user' ] = $USERINFO[ 'name' ];
                $_SESSION[ $conf[ 'title' ]][ 'auth' ][ 'info' ] = $USERINFO;
                
                $ValidUser = true;
            }
            else
            {   
                $ValidUser = false;
            }
        }
        
        // Is there a valid user login?
        if ( true != $ValidUser )
        {   
            // No, so make sure any existing authentication is revoked.
            auth_logoff ( );
        }
        
        return $ValidUser;
    }

    /**
     * Check user+password
     *
     * May be ommited if trustExternal is used.
     *
     * @param   string $user the user name
     * @param   string $pass the clear text password
     * @return  bool
     */
    public function checkPass($user, $pass) {
        // FIXME implement password check
        return false; // return true if okay
    }

    /**
     * Return user info
     *
     * Returns info about the given user needs to contain
     * at least these fields:
     *
     * name string  full name of the user
     * mail string  email addres of the user
     * grps array   list of groups the user is in
     *
     * @param   string $user the user name
     * @return  array containing user data or false
     */
    public function getUserData($user) {
      $data = array();
      
      $t_user_id = user_get_id_by_name( $user );
 
      if (isset($_REQUEST['media'])) {
          //media
          $t_project_name = explode( ':', getNS( getID("media",false) ) );
      } else {
          // normal page
          $t_project_name = explode( ':', getNS( getID() ) );
      }
 
      $t_project_id   = project_get_id_by_name( $t_project_name[1] );
      $t_access_level = access_get_project_level( $t_project_id, $t_user_id );
      $t_access_level_string    = strtoupper( MantisEnum::getLabel( config_get( 'access_levels_enum_string' ),  $t_access_level ) );
      $t_access_level_string_ex = strtoupper( $t_project_name[1] ) . '_' . $t_access_level_string;
      
      $data['name'] = $user;
      $data['grps'] = array( $t_access_level_string, $t_access_level_string_ex );
      $data['mail'] = user_get_email( $t_user_id );
      return $data;
    }

    /**
     * Create a new User [implement only where required/possible]
     *
     * Returns false if the user already exists, null when an error
     * occurred and true if everything went well.
     *
     * The new user HAS TO be added to the default group by this
     * function!
     *
     * Set addUser capability when implemented
     *
     * @param  string     $user
     * @param  string     $pass
     * @param  string     $name
     * @param  string     $mail
     * @param  null|array $grps
     * @return bool|null
     */
    //public function createUser($user, $pass, $name, $mail, $grps = null) {
        // FIXME implement
    //    return null;
    //}

    /**
     * Modify user data [implement only where required/possible]
     *
     * Set the mod* capabilities according to the implemented features
     *
     * @param   string $user    nick of the user to be changed
     * @param   array  $changes array of field/value pairs to be changed (password will be clear text)
     * @return  bool
     */
    //public function modifyUser($user, $changes) {
        // FIXME implement
    //    return false;
    //}

    /**
     * Delete one or more users [implement only where required/possible]
     *
     * Set delUser capability when implemented
     *
     * @param   array  $users
     * @return  int    number of users deleted
     */
    //public function deleteUsers($users) {
        // FIXME implement
    //    return false;
    //}

    /**
     * Bulk retrieval of user data [implement only where required/possible]
     *
     * Set getUsers capability when implemented
     *
     * @param   int   $start     index of first user to be returned
     * @param   int   $limit     max number of users to be returned
     * @param   array $filter    array of field/pattern pairs, null for no filter
     * @return  array list of userinfo (refer getUserData for internal userinfo details)
     */
    //public function retrieveUsers($start = 0, $limit = -1, $filter = null) {
        // FIXME implement
    //    return array();
    //}

    /**
     * Return a count of the number of user which meet $filter criteria
     * [should be implemented whenever retrieveUsers is implemented]
     *
     * Set getUserCount capability when implemented
     *
     * @param  array $filter array of field/pattern pairs, empty array for no filter
     * @return int
     */
    //public function getUserCount($filter = array()) {
        // FIXME implement
    //    return 0;
    //}

    /**
     * Define a group [implement only where required/possible]
     *
     * Set addGroup capability when implemented
     *
     * @param   string $group
     * @return  bool
     */
    //public function addGroup($group) {
        // FIXME implement
    //    return false;
    //}

    /**
     * Retrieve groups [implement only where required/possible]
     *
     * Set getGroups capability when implemented
     *
     * @param   int $start
     * @param   int $limit
     * @return  array
     */
    //public function retrieveGroups($start = 0, $limit = 0) {
        // FIXME implement
    //    return array();
    //}

    /**
     * Return case sensitivity of the backend
     *
     * When your backend is caseinsensitive (eg. you can login with USER and
     * user) then you need to overwrite this method and return false
     *
     * @return bool
     */
    public function isCaseSensitive() {
        return true;
    }

    /**
     * Sanitize a given username
     *
     * This function is applied to any user name that is given to
     * the backend and should also be applied to any user name within
     * the backend before returning it somewhere.
     *
     * This should be used to enforce username restrictions.
     *
     * @param string $user username
     * @return string the cleaned username
     */
    public function cleanUser($user) {
        return $user;
    }

    /**
     * Sanitize a given groupname
     *
     * This function is applied to any groupname that is given to
     * the backend and should also be applied to any groupname within
     * the backend before returning it somewhere.
     *
     * This should be used to enforce groupname restrictions.
     *
     * Groupnames are to be passed without a leading '@' here.
     *
     * @param  string $group groupname
     * @return string the cleaned groupname
     */
    public function cleanGroup($group) {
        return $group;
    }

    /**
     * Check Session Cache validity [implement only where required/possible]
     *
     * DokuWiki caches user info in the user's session for the timespan defined
     * in $conf['auth_security_timeout'].
     *
     * This makes sure slow authentication backends do not slow down DokuWiki.
     * This also means that changes to the user database will not be reflected
     * on currently logged in users.
     *
     * To accommodate for this, the user manager plugin will touch a reference
     * file whenever a change is submitted. This function compares the filetime
     * of this reference file with the time stored in the session.
     *
     * This reference file mechanism does not reflect changes done directly in
     * the backend's database through other means than the user manager plugin.
     *
     * Fast backends might want to return always false, to force rechecks on
     * each page load. Others might want to use their own checking here. If
     * unsure, do not override.
     *
     * @param  string $user - The username
     * @return bool
     */
    //public function useSessionCache($user) {
      // FIXME implement
    //}
}

// vim:ts=4:sw=4:et: