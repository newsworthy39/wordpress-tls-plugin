<?php
/**
 * @package TLS pluggable authentication
 * @version 1.0
 */
/*
Plugin Name: TLS Pluggable authentication
Plugin URI: http://github.com/newsworthy39/wordpress-tls-plugin
Description: This is not just plugin. Its a way of life.
Author: Newsworthy39 <newsworthy39@github.com>
Version: 1.0
Author URI: http://www.mjay.me
*/

$tls_db_version = "1.0";


/**
  * If the current request was signed using a valid OAuth access token, verify 
  * the request and return the associated user.
  *
  * @param WP_User|WP_Error|null $user authenticated user
  * @return WP_User|WP_Error|null OAuth authenticated user, if request was signed
  */
function tls_authenticate($user, $username, $password) {

	foreach($_SERVER as $key=>$item) {
//		print "$key=>$item</br>";
	}

	# User auth, through chains.
	$userobject = new stdClass();

	$userauthentication = ssl_client_cert_auth($userobject);

	$localuid           = ssl_client_cert_translate_to_uuid($userobject);

	if ($localuid !== false) {
		$user = new WP_user($localuid);
	}

	return $user;
}

# authentication
function ssl_client_cert_auth($obj, $ignore=true) {

	# if we don't ignore the verified header, we explicitly verify it.
	if (strtolower($_SERVER['SSL_CLIENT_VERIFY']) != 'success') {
		return false;
	}

	# tokenize this shit. We dont do passwords anymore.
	# its done. Pass. No. Adios.
	$subject_string = $_SERVER['SSL_CLIENT_S_DN'];
	$tokens = explode('/', $subject_string);
	foreach($tokens as $token) {
	  $values = explode('=', $token);
	  if (!empty($values[1])) {
		  $obj->{$values[0]} = $values[1] ;
	  }
	}

	# We can revoke access, if only we have setup ca-chains and stuff.
	$obj->{'SSL_CLIENT_CERT'} = $_SERVER['SSL_CLIENT_CERT'];

	# Return ok (naive)
	return true;
}

# translate to local user_accounts.
function ssl_client_cert_translate_to_uuid($obj) {

	global $wpdb;

	$table_name = $wpdb->prefix . 'tls_wpuser_mapping';

	$sql  = $wpdb->prepare( 
		"SELECT wp_userid FROM $table_name where SSL_CLIENT_S_DN_EMAIL = %s and SSL_CLIENT_CERT_SHA256 = %s ", 
        	$obj->{'emailAddress'}, 
		hash('sha256', $obj->{'SSL_CLIENT_CERT'})
	) ;

	$candidates = $wpdb->get_results($sql, "ARRAY_N");

    	foreach($candidates as $row=>$item) {
		return $item[0];
    	}

	return false;

}

function tls_install_db() {


	// Check if we should upgrade tables, by asking if adblock_list_db_version is different than
	// get_option('adblock_db_version')..
	global $wpdb;
	global $tls_db_version;

	$table_name = $wpdb->prefix . 'tls_wpuser_mapping';

	$charset_collate = $wpdb->get_charset_collate();

	$sql = "CREATE TABLE IF NOT EXISTS $table_name (
                id mediumint(9) NOT NULL AUTO_INCREMENT,
                SSL_CLIENT_S_DN_EMAIL varchar(255) NOT NULL,
		SSL_CLIENT_CERT_SHA256 CHAR(64) NOT NULL,
                wp_userid mediumint(9) not null,
                PRIMARY KEY (id)
        ) $charset_collate; ";

	// Create plugin table (if not exists)
	$wpdb->query($sql);

	// Add the table option
	add_option('tls_db_version', $tls_db_version);
}


function tls_uninstall_db() {
	global $wpdb;
	global $tls_list_db_version;
 	$table_name = $wpdb->prefix . 'tls_wpuser_mapping';
	$sql = "DROP TABLE IF EXISTS $table_name;";
	$wpdb->query($sql);

	// make sure, we provide this for upgrade of db-schemas.
	delete_option('tls_db_version', $tls_db_version);

}

/**
 * Install Plugin-routines.
 */
register_deactivation_hook(__FILE__, 'tls_uninstall_db');
register_activation_hook(__FILE__, 'tls_install_db') ;

/**
 * Add filters 
 */
add_filter('authenticate', 'tls_authenticate', 30, 3);

/** 
 *Add actions 
 */
add_action( 'show_user_profile', 'extra_user_profile_fields' );
add_action( 'edit_user_profile', 'extra_user_profile_fields' );

function extra_user_profile_fields($user) {
	global $wpdb;
	$table_name = $wpdb->prefix . 'tls_wpuser_mapping';

	# User auth, through chains.
	$userobject = new stdClass();

        if(ssl_client_cert_auth($userobject)) {

//		$sql = $wpdb->query( $wpdb->prepare("SELECT /* extra_user_profile_fields*/ SSL_CLIENT_S_DN_EMAIL FROM $table_name WHERE wp_userid = %d", $user->ID ) );

//		$candidates = $wpdb->get_results($sql, "ARRAY_N");

		print "<table class='form-table'>";
print '<tr>';
print '<th><label for="SSLDNEmailAddress">SSLDNEmailAddress</label></th>';
print '<td>';
print '<input type="text" name="SSLDNEmailAddress" id="SSLDNEmailAddress" value="' . $userobject->{'emailAddress'} .'" class="regular-text" /><br />';
print '<span class="description">Assign this certificate to your user</span>';
print '</td>';
print '</tr></table>';

	}	

}

// add save action.
add_action( 'personal_options_update', 'update_extra_profile_fields');

function update_extra_profile_fields($user_id) {
	global $wpdb;

	$table_name = $wpdb->prefix . 'tls_wpuser_mapping';

	 # User auth, through chains.
        $userobject = new stdClass();

        ssl_client_cert_auth($userobject);

	$clientsha256 = hash('sha256', $userobject->{'SSL_CLIENT_CERT'});

	if (current_user_can('edit_user', $user_id)) {

		$sql = $wpdb->prepare("SELECT /*update_extra_profile_fields */ SSL_CLIENT_CERT_SHA256 FROM $table_name WHERE wp_userid = %d", $user_id );
                $list = $wpdb->get_results($sql, "ARRAY_N");

		$found = false;
                foreach($list as $row=>$item) {
                        if ($item[0] == $clientsha256) {
				$found = true;
			}
                }

		
		if(!$found) {		
			$wpdb->query( $wpdb->prepare("INSERT INTO $table_name (SSL_CLIENT_S_DN_EMAIL, SSL_CLIENT_CERT_SHA256, wp_userid) VALUES (%s, %s, %d)", $_POST['SSLDNEmailAddress'], $clientsha256 , $user_id) );
		}
	}
}
