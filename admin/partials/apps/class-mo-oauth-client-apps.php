<?php


require('partials'.DIRECTORY_SEPARATOR.'sign-in-settings.php');
require('partials'.DIRECTORY_SEPARATOR.'customization.php');
require('partials'.DIRECTORY_SEPARATOR.'addapp.php');
require('partials'.DIRECTORY_SEPARATOR.'updateapp.php');
require('partials'.DIRECTORY_SEPARATOR.'app-list.php');
require('partials'.DIRECTORY_SEPARATOR.'attr-role-mapping.php');

class MOOAuth_Client_Admin_Apps {
	
	public static function sign_in_settings() {
		mooauth_client_sign_in_settings_ui();
	}
	
	public static function customization() {
		mooauth_client_customization_ui();
	}
	
	public static function applist() {
		mooauth_client_applist_page();
	}
	
	public static function add_app() {
		mooauth_client_add_app_page();
	}
	
	public static function update_app($appname) {
		mooauth_client_update_app_page($appname);
	}

	public static function attribute_role_mapping() {
		mooauth_client_attribite_role_mapping_ui();
	}
}

?>