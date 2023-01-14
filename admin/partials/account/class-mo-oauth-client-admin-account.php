<?php


require('partials'.DIRECTORY_SEPARATOR.'register.php');
require('partials'.DIRECTORY_SEPARATOR.'verify-password.php');

class MOOAuth_Client_Admin_Account {
	
	public static function register() {
		if ( ! mooauth_is_customer_registered() ) {
			mooauth_client_register_ui();
		} else {
			mooauth_client_show_customer_info();
		}
	}
	
	public static function verify_password() {
		mooauth_client_verify_password_ui();
	}
	
	public static function otp_verification() {
	}

}

?>