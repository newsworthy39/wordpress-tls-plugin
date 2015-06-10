<?php
/**
 * @package TLS pluggable authentication
 * @version 1.0
 */
/*
Plugin Name: TLS Pluggable authentication
Plugin URI: http://github.com/newsworthy39/wordpress-tls-plugin
Description: This is not just plugin. Its a way of life.
Author: newsworthy39
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
	$obj->{'SN'} = $_SERVER['SSL_CLIENT_M_SERIAL'];

	# Return ok (naive)
	return true;
}

# translate to local user_accounts.
function ssl_client_cert_translate_to_uuid($obj) {

	global $wpdb;

	$table_name = $wpdb->prefix . 'tls_wpuser_mapping';

	$sql = "SELECT wp_userid FROM $table_name where SSL_CLIENT_M_SERIAL = '" . $obj->{'SN'} . "'";

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
                SSL_CLIENT_M_SERIAL varchar(32) NOT NULL,
                wp_userid mediumt(9) not null,
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
