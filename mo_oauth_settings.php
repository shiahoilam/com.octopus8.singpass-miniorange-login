<?php
/**
 * Plugin Name: SingPass
 * Base Plugin: OAuth Single Sign On - SSO (OAuth Client)
 * Base Plugin URI: miniorange-login-with-eve-online-google-facebook
 * Description: This WordPress Single Sign-On plugin allows login into WordPress with your SingPass or other custom OAuth 2.0 / OpenID Connect providers. WordPress OAuth Client plugin works with any Identity provider that conforms to the OAuth 2.0 and OpenID Connect (OIDC) 1.0 standard.
 * Version: 1.00.1
 * Author: Khindol Madraimov, miniOrange
 * Author Email: khindol.madraimov@gmail.com
 * Author URI: https://www.miniorange.com
 * License: MIT/Expat
 * License URI: https://docs.miniorange.com/mit-license
 * Text Domain: miniorange-login-with-eve-online-google-facebook
 * Domain Path: /languages
*/

require('handler'.DIRECTORY_SEPARATOR.'oauth_handler.php');
include_once dirname( __FILE__ ).DIRECTORY_SEPARATOR.'class-mo-oauth-widget.php';
require('class-customer.php');
require plugin_dir_path( __FILE__ ) . 'includes'.DIRECTORY_SEPARATOR.'class-mo-oauth-client.php';
require('views'.DIRECTORY_SEPARATOR.'feedback_form.php');
require('admin'.DIRECTORY_SEPARATOR.'partials'.DIRECTORY_SEPARATOR.'setup_wizard'.DIRECTORY_SEPARATOR.'handler'.DIRECTORY_SEPARATOR.'mo-oauth-wizard-ajax.php');
require('admin'.DIRECTORY_SEPARATOR.'partials'.DIRECTORY_SEPARATOR.'setup_wizard'.DIRECTORY_SEPARATOR.'class-mo-oauth-client-setup-wizard.php');
require('constants.php');
include_once dirname( __FILE__ ).DIRECTORY_SEPARATOR.'mosingpass-wordpress-plugin.php';

define( 'MO_OAUTH_CSS_JS_VERSION', '6.23.7' );
class MOOAuth {

	function __construct() {

		add_action( 'admin_init',  array( $this, 'miniorange_oauth_save_settings' ),11 );
		//add_action( 'plugins_loaded',  array( $this, 'mo_login_widget_text_domain' ) );
		add_action('plugins_loaded',array($this,'mo_load_plugin_textdomain'));
		register_deactivation_hook(__FILE__, array( $this, 'mo_oauth_deactivate'));
		register_activation_hook(__FILE__, array($this,'mo_oauth_set_cron_job'));		
		register_activation_hook(__FILE__, array($this,'mo_oauth_activate'));
		add_shortcode('mo_oauth_login', array( $this,'mo_oauth_shortcode_login'));
		add_action( 'admin_footer', array( $this, 'mo_oauth_client_feedback_request' ) );
		add_action( 'check_if_wp_rest_apis_are_open', array( $this, 'mo_oauth_scheduled_task' ) );
		add_action('upgrader_process_complete', array($this,'mo_oauth_upgrade_hook'),10,2);

		add_action( 'admin_init'  , array( $this, 'mo_oauth_debug_log_ajax_hook' ) );
		add_action( 'admin_init'  , array( $this, 'mo_oauth_client_support_script_hook' ) );

	}

	function mo_oauth_client_support_script_hook(){
		if(isset($_REQUEST['page']) && $_REQUEST['page'] == 'mo_oauth_settings'){
			if(!(isset($_REQUEST['tab']) && $_REQUEST['tab'] == 'licensing')){
				wp_enqueue_script( 'mo_oauth_client_support_script', plugin_dir_url( __FILE__ ) . '/admin/js/clientSupport.js', array(), $ver = "10.0.0", $in_footer = false );
			}
		}
	}

	function mo_oauth_debug_log_ajax_hook(){
		add_action( 'wp_ajax_mo_oauth_debug_ajax', array($this,'mo_oauth_debug_log_ajax') );
	}

	function mo_oauth_debug_log_ajax(){
		if(!isset($_POST['mo_oauth_nonce']) || !wp_verify_nonce(sanitize_text_field($_POST['mo_oauth_nonce']),'mo-oauth-Debug-logs-unique-string-nonce'))
		{	
			wp_send_json('error');	
		}else{
			switch(sanitize_text_field($_POST['mo_oauth_option']))
			{
			case 'mo_oauth_reset_debug':
				$this->mo_oauth_reset_debug();break;	
			}
		}
		
	}

// wp_once_field configuration by ajax call submition.

	function mo_oauth_reset_debug(){
		if( isset( $_POST['mo_oauth_option'] ) and sanitize_text_field( wp_unslash( $_POST['mo_oauth_option'] ) ) == "mo_oauth_reset_debug" && isset( $_REQUEST['mo_oauth_nonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_REQUEST['mo_oauth_nonce'] ) ), 'mo-oauth-Debug-logs-unique-string-nonce' ))
		{
			$debug_enable = false;
			if(isset($_POST['mo_oauth_mo_oauth_debug_check'])) {
				$debug_enable = sanitize_text_field($_POST['mo_oauth_mo_oauth_debug_check']);
			}
			update_option('mo_debug_enable',$debug_enable);
			if( get_option('mo_debug_enable') ){
				update_option('mo_debug_check',1);
			}	
	
			if( get_option('mo_debug_enable') ){
				update_option('mo_oauth_debug','mo_oauth_debug'.uniqid());
				$mo_oauth_debugs=get_option('mo_oauth_debug');
				$mo_file_addr2=dirname(__FILE__).DIRECTORY_SEPARATOR.$mo_oauth_debugs.'.log';
				$mo_debug_file=fopen($mo_file_addr2,"w");
				chmod($mo_file_addr2,0644);
				update_option( 'mo_debug_check',1 );
				MOOAuth_Debug::mo_oauth_log('');
				update_option( 'mo_debug_check',0 );
			}
			
			$switch_status= get_option('mo_debug_enable');
			$response['switch_status']= $switch_status;
			wp_send_json($response);
		}else{echo 'error';}
	}


	public function mo_load_plugin_textdomain() {
		load_plugin_textdomain(
			'miniorange-login-with-eve-online-google-facebook',
			false,
			basename( dirname( __FILE__ ) ) . DIRECTORY_SEPARATOR. 'languages'
		);
	}

	function mo_oauth_success_message() {
		$class = "error";
		$message = get_option('message');
		echo "<div class='" . esc_attr( $class ) . "'> <p>" . esc_attr( $message ) . "</p></div>";
	}

	function mo_oauth_client_feedback_request() {
		mooauth_client_display_feedback_form();
	}

	function mo_oauth_error_message() {
		$class = "updated";
		$message = get_option('message');
		echo "<div class='" . esc_attr( $class ) . "'><p>" . esc_attr( $message ) . "</p></div>";
	}
	/*
		*   Custom Intervals
		*	Name             dispname                Interval
		*   three_minutes    Every Three minutes	 3  * MINUTE_IN_SECONDS (3 * 60)
		*   five_minutes     Every Five minutes	     5  * MINUTE_IN_SECONDS (5 * 60)
		*   ten_minutes      Every Ten minutes	     10 * MINUTE_IN_SECONDS (10 * 60)
		*   three_days     	 Every Three days	     3  * 24 * 60 * MINUTE_IN_SECONDS
		*   five_days      	 Every Five days	     5  * 24 * 60 * MINUTE_IN_SECONDS
		*
		*
		*   Default Intervals
		*   Name         dispname        Interval (in sec)
		*   hourly       Once Hourly	 3600 (1 hour)
		*   twicedaily   Twice Daily	 43200 (12 hours)
		*   daily        Once Daily	     86400 (1 day) 
		*   weekly       Once Weekly	 604800 (1 week) 
	*/

	public function mo_oauth_set_cron_job()
	{
		
		//add_filter( 'cron_schedules', array($this,'add_cron_interval'));// uncomment this for custom intervals
		
		if (!wp_next_scheduled('check_if_wp_rest_apis_are_open')) {
			
			//$custom_interval=apply_filters('cron_schedules',array('three_minutes'));//uncomment this for custom interval		
      		wp_schedule_event( time()+604800, 'weekly', 'check_if_wp_rest_apis_are_open' );// update timestamp and name according to interval
 		}
 	}
 	public function  mo_oauth_activate(){
		$activate_time = new DateTime();
		update_option("mo_oauth_activation_time", $activate_time);
 		add_option('mo_oauth_do_activation_redirect', true);
	}
	public function mo_oauth_deactivate() {
		delete_option('host_name');
		delete_option('mo_oauth_client_new_registration');
		delete_option('mo_oauth_client_admin_phone');
		delete_option('mo_oauth_client_verify_customer');
		delete_option('mo_oauth_client_admin_customer_key');
		delete_option('mo_oauth_client_admin_api_key');
		delete_option('mo_oauth_client_new_customer');
		delete_option('mo_oauth_client_customer_token');
		delete_option('message');
		delete_option('mo_oauth_client_registration_status');
		delete_option('mo_oauth_client_show_mo_server_message');
		delete_option('mo_oauth_log');
		delete_option('mo_oauth_debug');
		wp_clear_scheduled_hook( 'check_if_wp_rest_apis_are_open' );
	}


		function add_cron_interval( $schedules ) { 
		
		if(isset($schedules['three_minutes']))
		{
    		$schedules['three_minutes'] = array(
        	'interval' => 3 * MINUTE_IN_SECONDS,
        	'display'  => esc_html__( 'Every Three minutes' ), );
		}else if(isset($schedules['five_minutes']))
		{
    		$schedules['five_minutes'] = array(
        	'interval' => 5 * MINUTE_IN_SECONDS,
        	'display'  => esc_html__( 'Every Five minutes' ), );
		}else if(isset($schedules['ten_minutes']))
		{
    		$schedules['ten_minutes'] = array(
        	'interval' => 10 * MINUTE_IN_SECONDS,
        	'display'  => esc_html__( 'Every Ten minutes' ), );
		}else if(isset($schedules['three_days']))
		{
    		$schedules['three_days'] = array(
        	'interval' => 3 * 24 * 60 * MINUTE_IN_SECONDS,
        	'display'  => esc_html__( 'Every Three days' ), );
		}else if(isset($schedules['five_days']))
		{
    		$schedules['five_days'] = array(
        	'interval' => 5 * 24 * 60 * MINUTE_IN_SECONDS,
        	'display'  => esc_html__( 'Every Five days' ), );
		}
		
    return $schedules;
}

	function mo_oauth_scheduled_task() {    
    	$url=site_url()."/wp-json/wp/v2/posts";
    	$response = wp_remote_get($url, array(
			'method' => 'GET',
			'timeout' => 45,
			'redirection' => 5,
			'httpversion' => 1.0,
			'blocking' => true,
			'headers' => array(),
			'cookies' => array(),
			'sslverify' => false,
		));
    	
    	if(is_wp_error( $response ))
    	{
    		if(is_object($response))
    			error_log(print_r(sanitize_text_field($response->errors),TRUE));
    		return;
    	}
    	$code=wp_remote_retrieve_response_code($response);
    	if(isset($code) && $code=='200')
    	{    		
    		if(isset($response))
    		{
    			update_option( 'mo_oauth_client_show_rest_api_message', true);	
    		}
    		
    	}		
    	
    	
  }


	function mo_login_widget_text_domain(){
		load_plugin_textdomain( 'flw', FALSE, basename( dirname( __FILE__ ) ) .DIRECTORY_SEPARATOR. 'languages' );
	}

	private function mo_oauth_show_success_message() {
		remove_action( 'admin_notices', array( $this, 'mo_oauth_success_message') );
		add_action( 'admin_notices', array( $this, 'mo_oauth_error_message') );
	}

	private function mo_oauth_show_error_message() {
		remove_action( 'admin_notices', array( $this, 'mo_oauth_error_message') );
		add_action( 'admin_notices', array( $this, 'mo_oauth_success_message') );
	}

	public function mo_oauth_check_empty_or_null( $value ) {
		if( ! isset( $value ) || empty( $value ) ) {
			return true;
		}
		return false;
	}

	function miniorange_oauth_save_settings(){
		if(get_option('mo_oauth_do_activation_redirect')){
			delete_option('mo_oauth_do_activation_redirect');
			if(get_option('mo_oauth_apps_list') || get_option('mo_oauth_setup_wizard_app'))
 				wp_safe_redirect(admin_url( 'admin.php?page=mo_oauth_settings&tab=config' ));
 			else
 				wp_safe_redirect(admin_url( 'admin.php?option=mo_oauth_client_setup_wizard' ));
		}
		if(isset( $_GET['option'] ) and "mo_oauth_client_setup_wizard" == sanitize_text_field( wp_unslash( $_GET['option'] ) )){
			if( current_user_can( 'administrator' ) ) {
				$setup_wizard = new MOOAuth_Client_Setup_Wizard();
				$setup_wizard->page();
				return;
			}
			else {
				wp_die("Sorry, you are not allowed to access this page.");
			}
		}
		if ( isset( $_POST['option'] ) and sanitize_text_field( wp_unslash( $_POST['option'] ) ) == "mo_oauth_client_mo_server_message" && isset( $_REQUEST['mo_oauth_mo_server_message_form_field'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_REQUEST['mo_oauth_mo_server_message_form_field'] ) ), 'mo_oauth_mo_server_message_form' )) {
			update_option( 'mo_oauth_client_show_mo_server_message', 1 );
			return;
		}
		if ( isset( $_POST['option'] ) and sanitize_text_field( wp_unslash( $_POST['option'] ) ) == "mo_oauth_client_rest_api_message" && isset( $_REQUEST['mo_oauth_client_rest_api_form_field'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_REQUEST['mo_oauth_client_rest_api_form_field'] ) ), 'mo_oauth_client_rest_api_form' )) {
			
			delete_option('mo_oauth_client_show_rest_api_message');
			wp_clear_scheduled_hook( 'check_if_wp_rest_apis_are_open' );
			return;
		}

		if ( isset( $_POST['option'] ) and sanitize_text_field( wp_unslash( $_POST['option'] ) ) == "clear_pointers" && isset( $_REQUEST['mo_oauth_clear_pointers_form_field'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_REQUEST['mo_oauth_clear_pointers_form_field'] ) ), 'mo_oauth_clear_pointers_form' )) {
			update_user_meta(get_current_user_id(),'dismissed_wp_pointers','');
			return;
		}

		if ( isset( $_POST['option'] ) and sanitize_text_field( wp_unslash( $_POST['option'] ) ) == "change_miniorange" && isset( $_REQUEST['mo_oauth_goto_login_form_field'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_REQUEST['mo_oauth_goto_login_form_field'] ) ), 'mo_oauth_goto_login_form' )) {
			if( current_user_can( 'administrator' ) ) {
				$this->mo_oauth_deactivate();
				return;
			}
		}

		
		if( isset( $_POST['option'] ) and sanitize_text_field( wp_unslash( $_POST['option'] ) ) == "mo_oauth_clear_debug" && isset( $_REQUEST['mo_oauth_clear_debug_nonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_REQUEST['mo_oauth_clear_debug_nonce'] ) ), 'mo_oauth_clear_debug' ))
			{

				if( get_option('mo_debug_enable')){
					update_option('mo_oauth_debug','mo_oauth_debug'.uniqid());
					$mo_oauth_debugs=get_option('mo_oauth_debug');
					$mo_file_addr2=dirname(__FILE__).DIRECTORY_SEPARATOR.$mo_oauth_debugs.'.log';
					$mo_debug_file=fopen($mo_file_addr2,"w");
					chmod($mo_file_addr2,0644);
					update_option( 'mo_debug_check',1 );
					MOOAuth_Debug::mo_oauth_log('');
					update_option( 'mo_debug_check',0 );
				}
			return;
		}

		if( isset( $_POST['option'] ) and sanitize_text_field( wp_unslash( $_POST['option'] ) ) == "mo_oauth_enable_debug_download" && isset( $_REQUEST['mo_oauth_enable_debug_download_nonce'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_REQUEST['mo_oauth_enable_debug_download_nonce'] ) ), 'mo_oauth_enable_debug_download' ))
			{
				$mo_filepath=plugin_dir_path(__FILE__).get_option('mo_oauth_debug').'.log';

				if (!is_file($mo_filepath)) {
					 echo("404 File not found!"); // file not found to download
					 exit();
			    }

			    $mo_len = filesize($mo_filepath); // get size of file
				$mo_filename = basename($mo_filepath); // get name of file only
				$mo_file_extension = strtolower(pathinfo($mo_filename,PATHINFO_EXTENSION));
				//Set the Content-Type to the appropriate setting for the file
				$mo_ctype="application/force-download";
				ob_clean();
				//Begin writing headers
				header("Pragma: public");
				header("Expires: 0");
				header("Cache-Control: must-revalidate, post-check=0, pre-check=0");
				header("Cache-Control: public"); 
				header("Content-Description: File Transfer");
				header("Content-Type: $mo_ctype");
				//Force the download
				$mo_header="Content-Disposition: attachment; filename=".$mo_filename.";";
				header($mo_header );
				header("Content-Transfer-Encoding: binary");
				header("Content-Length: ".$mo_len);
				@readfile($mo_filepath);
				exit;
		}

		if( isset( $_POST['option'] ) and sanitize_text_field( wp_unslash( $_POST['option'] ) ) == "mo_oauth_register_customer" && isset( $_REQUEST['mo_oauth_register_form_field'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_REQUEST['mo_oauth_register_form_field'] ) ), 'mo_oauth_register_form' )) {
			if( current_user_can( 'administrator' ) ) {
				$email = '';
				$phone = '';
				$password = '';
				$confirmPassword = '';
				$fname = '';
				$lname = '';
				$company = '';
				if( $this->mo_oauth_check_empty_or_null( sanitize_text_field($_POST['email']) ) || $this->mo_oauth_check_empty_or_null( sanitize_text_field($_POST['password']) ) || $this->mo_oauth_check_empty_or_null( sanitize_text_field($_POST['confirmPassword']) ) ) {
					update_option( 'message', 'All the fields are required. Please enter valid entries.');
					$this->mo_oauth_show_error_message();
					return;
				} else if( strlen( sanitize_text_field($_POST['password']) ) < 8 || strlen( sanitize_text_field($_POST['confirmPassword']) ) < 8){
					update_option( 'message', 'Choose a password with minimum length 8.');
					$this->mo_oauth_show_error_message();
					return;
				} else{
					$email = sanitize_email( $_POST['email'] );
					$phone = stripslashes( sanitize_text_field($_POST['phone']) );
					$password = stripslashes( ($_POST['password']) );
					$confirmPassword = stripslashes( ($_POST['confirmPassword']) );
					$fname = sanitize_text_field(wp_unslash(stripslashes( $_POST['fname'] )));
					$lname = sanitize_text_field(wp_unslash(stripslashes( $_POST['lname'] )));
					$company = sanitize_text_field(wp_unslash(stripslashes( $_POST['company'] )));
				}

				update_option( 'mo_oauth_admin_email', $email );
				update_option( 'mo_oauth_client_admin_phone', $phone );
				update_option( 'mo_oauth_admin_fname', $fname );
				update_option( 'mo_oauth_admin_lname', $lname );
				update_option( 'mo_oauth_admin_company', $company );

				if( mooauth_is_curl_installed() == 0 ) {
					return $this->mo_oauth_show_curl_error();
				}

				if( strcmp( $password, $confirmPassword) == 0 ) {
					update_option( 'password', $password );
					$customer = new MOOAuth_Client_Customer();
					$email=get_option('mo_oauth_admin_email');
					$content = json_decode($customer->check_customer(), true);
					if( strcasecmp( $content['status'], 'CUSTOMER_NOT_FOUND') == 0 ){
						$response = json_decode($customer->create_customer(), true);
						if(strcasecmp($response['status'], 'SUCCESS') == 0) {
							$this->mo_oauth_get_current_customer();
							wp_redirect( admin_url( '/admin.php?page=mo_oauth_settings&tab=licensing' ), 301 );
							exit;
						} if( strcasecmp($response['status'], 'FAILED') == 0 && strcasecmp($response['message'], 'Email is not enterprise email.') == 0 ) {
                            update_option( 'message', 'Please use your Enterprise email for registration.');
                        } else {
							update_option( 'message', 'Failed to create customer. Try again.');
						}
						$this->mo_oauth_show_success_message();
					} else {
						$this->mo_oauth_get_current_customer();
					}
				} else {
					update_option( 'message', 'Passwords do not match.');
					delete_option('mo_oauth_client_verify_customer');
					$this->mo_oauth_show_error_message();
				}
			}
		}

		if( isset( $_POST['option'] ) and sanitize_text_field( wp_unslash( $_POST['option'] ) ) == "mo_oauth_client_goto_login" && isset( $_REQUEST['mo_oauth_goto_login_form_field'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_REQUEST['mo_oauth_goto_login_form_field'] ) ), 'mo_oauth_goto_login_form' )) {
			delete_option( 'mo_oauth_client_new_registration' );
			update_option( 'mo_oauth_client_verify_customer', 'true' );
		}

		if( isset( $_POST['option'] ) and sanitize_text_field( wp_unslash( $_POST['option'] ) ) == "mo_oauth_verify_customer" && isset( $_REQUEST['mo_oauth_verify_password_form_field'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_REQUEST['mo_oauth_verify_password_form_field'] ) ), 'mo_oauth_verify_password_form' )) 
		{	//register the admin to miniOrange
			if( current_user_can( 'administrator' ) ) {
				if( mooauth_is_curl_installed() == 0 ) {
					return $this->mo_oauth_show_curl_error();
				}
				//validation and sanitization
				$email = '';
				$password = '';
				if( $this->mo_oauth_check_empty_or_null( sanitize_text_field($_POST['email']) ) || $this->mo_oauth_check_empty_or_null( sanitize_text_field($_POST['password']) ) ) {
					update_option( 'message', 'All the fields are required. Please enter valid entries.');
					$this->mo_oauth_show_error_message();
					return;
				} else{
					$email = sanitize_email( $_POST['email'] );
					$password = stripslashes( sanitize_text_field($_POST['password']) );
				}

				update_option( 'mo_oauth_admin_email', $email );
				update_option( 'password', $password );
				$customer = new MOOAuth_Client_Customer();
				$content = $customer->get_customer_key();
				$customerKey = json_decode( $content, true );
				if( json_last_error() == JSON_ERROR_NONE ) {
					update_option( 'mo_oauth_client_admin_customer_key', $customerKey['id'] );
					update_option( 'mo_oauth_client_admin_api_key', $customerKey['apiKey'] );
					update_option( 'mo_oauth_client_customer_token', $customerKey['token'] );
					if( isset( $customerKey['phone'] ) )
						update_option( 'mo_oauth_client_admin_phone', $customerKey['phone'] );
					delete_option('password');
					update_option( 'message', 'Customer retrieved successfully');
					delete_option('mo_oauth_client_verify_customer');
					delete_option('mo_oauth_client_new_registration');
					$this->mo_oauth_show_success_message();
				} else {
					update_option( 'message', 'Invalid username or password. Please try again.');
					$this->mo_oauth_show_error_message();
				}
			}
		} 
		else if( isset( $_POST['option'] ) and sanitize_text_field( wp_unslash( $_POST['option'] ) ) == "mo_oauth_add_app" && isset( $_REQUEST['mo_oauth_add_app_form_field'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_REQUEST['mo_oauth_add_app_form_field'] ) ), 'mo_oauth_add_app_form' )) {
			if( current_user_can( 'administrator' ) ) {
				$scope = '';
				$clientid = '';
				$clientsecret = '';
				if($this->mo_oauth_check_empty_or_null($_POST['mo_oauth_client_id']) || $this->mo_oauth_check_empty_or_null($_POST['mo_oauth_client_secret'])) {
					update_option( 'message', 'Please enter valid Client ID and Client Secret.');
					$this->mo_oauth_show_error_message();
					return;
				} else {
                    $callback_url=site_url();
                    $scope = isset($_POST['mo_oauth_scope']) ? stripslashes(sanitize_text_field($_POST['mo_oauth_scope'])) : "";
                    $clientid = stripslashes($_POST['mo_oauth_client_id']);
                    $clientsecret = stripslashes($_POST['mo_oauth_client_secret']);
                    $appname = rtrim(stripslashes( sanitize_text_field($_POST['mo_oauth_custom_app_name']) ), " ");
                    $ssoprotocol = stripslashes(sanitize_text_field($_POST['mo_oauth_app_type']));
                    $selectedapp = stripslashes(sanitize_text_field($_POST['mo_oauth_app_name']));
                    $send_headers = isset($_POST['mo_oauth_authorization_header']) ? sanitize_post($_POST['mo_oauth_authorization_header']) : "0";
                    $send_body = isset($_POST['mo_oauth_body']) ? sanitize_post($_POST['mo_oauth_body']) : "0";
                    $send_state=isset($_POST['mo_oauth_state']) ? (int)filter_var(sanitize_text_field($_POST['mo_oauth_state']), FILTER_SANITIZE_NUMBER_INT) : 0;
                    $show_on_login_page = isset($_POST['mo_oauth_show_on_login_page']) ? (int)filter_var(sanitize_text_field($_POST['mo_oauth_show_on_login_page']), FILTER_SANITIZE_NUMBER_INT) : 0;

                    if ($selectedapp == 'wso2') {
                        update_option('mo_oauth_client_custom_token_endpoint_no_csecret', true);
                    }

                    if (get_option('mo_oauth_apps_list'))
                        $appslist = get_option('mo_oauth_apps_list');
                    else
                        $appslist = array();

					$email_attr = "";
					$name_attr = "";
                    $newapp = array();

                    $isupdate = false;
                    foreach ($appslist as $key => $currentapp) {
                        if ($appname == $key) {
                            $newapp = $currentapp;
                            $isupdate = true;
                            break;
                        }
                    }

                    if (!$isupdate && sizeof($appslist) > 0) {
                        update_option('message', 'You can only add 1 application with free version. Upgrade to enterprise version if you want to add more applications.');
                        $this->mo_oauth_show_error_message();
                        return;
                    }


					$newapp['clientid'] = $clientid;
					$newapp['clientsecret'] = $clientsecret;
					$newapp['scope'] = $scope;
					$newapp['redirecturi'] = $callback_url;
					$newapp['ssoprotocol'] = $ssoprotocol;
                    $newapp['send_headers'] = $send_headers;
                    $newapp['send_body'] = $send_body;
                    $newapp['send_state']=$send_state;
                    $newapp['show_on_login_page'] = $show_on_login_page;
                   
                    if($appname == 'oauth1' || $appname == 'twitter'){
                    	$newapp['requesturl'] = isset($_POST['mo_oauth_requesturl']) ? stripslashes(sanitize_text_field($_POST['mo_oauth_requesturl'])) : "";
                    }
                    
                    if (isset($_POST['mo_oauth_app_type'])) {
                        $newapp['apptype'] = stripslashes(sanitize_text_field($_POST['mo_oauth_app_type']));
                    } else {
                        $newapp['apptype'] = stripslashes('oauth');
                    }

                    if(isset($_POST['mo_oauth_app_name'])) {
                        $newapp['appId'] = sanitize_text_field( $_POST['mo_oauth_app_name'] );
                    }

                    if (isset($_POST['mo_oauth_discovery']) && $_POST['mo_oauth_discovery'] != "") {
                        add_option('mo_existing_app_flow', true);
                        $newapp['existing_app_flow'] = true;
                        $discovery_endpoint = sanitize_text_field(wp_unslash($_POST['mo_oauth_discovery']));
                        if(isset($_POST['mo_oauth_provider_domain'])) {
                            $domain = stripslashes(rtrim(sanitize_text_field($_POST['mo_oauth_provider_domain'],"/")));
                            $discovery_endpoint = str_replace("domain", $domain, $discovery_endpoint);
                            $newapp['domain'] = $domain;
                        } elseif(isset($_POST['mo_oauth_provider_tenant'])) {
                            $tenant = stripslashes(trim(sanitize_text_field($_POST['mo_oauth_provider_tenant'])));
                            $discovery_endpoint = str_replace("tenant", $tenant, $discovery_endpoint);
                            $newapp['tenant'] = $tenant;
                        }

                        if(isset($_POST['mo_oauth_provider_policy'])) {
                            $policy = stripslashes(trim(sanitize_text_field($_POST['mo_oauth_provider_policy'])));
                            $discovery_endpoint = str_replace("policy", $policy, $discovery_endpoint);
                            $newapp['policy'] = $policy;
                        } elseif(isset($_POST['mo_oauth_provider_realm'])) {
                            $realm = stripslashes(trim(sanitize_text_field($_POST['mo_oauth_provider_realm'])));
                            $discovery_endpoint = str_replace("realmname", $realm, $discovery_endpoint);
                            $newapp['realm'] = $realm;
                        }

                        $provider_se = null;

                        if((filter_var($discovery_endpoint, FILTER_VALIDATE_URL))){
                            $content=wp_remote_get($discovery_endpoint,array('sslverify'=> false));
							if( !empty($newapp['realm']) && wp_remote_retrieve_response_code( $content ) !== 200 ){			
								$discovery_endpoint = str_replace('/auth','', $discovery_endpoint);
								$content=wp_remote_get($discovery_endpoint, array('sslverify' => false));
							}
							$provider_se = array();
							if(!is_wp_error($content) && wp_remote_retrieve_response_code( $content ) === 200){
								$content = wp_remote_retrieve_body($content);		
								$provider_se=json_decode($content);    
	                            $scope1 = isset($provider_se->scopes_supported[0])?$provider_se->scopes_supported[0] : "";
	                            $scope2 = isset($provider_se->scopes_supported[1])?$provider_se->scopes_supported[1] : "";
	                            $openid = '';
	                            if($scope1 != 'openid' && $scope2 != 'openid' && in_array('openid', $provider_se->scopes_supported))
	                            	$openid = 'openid';
	                            if($openid != '')
	                            	$pscope = $openid." ".stripslashes($scope1)." ".stripslashes($scope2);
	                            else 
	                            	$pscope = stripslashes($scope1)." ".stripslashes($scope2);

	                            $newapp['scope'] = (isset($scope) && $scope != "" ) ? $scope : $pscope;
	                            $newapp['authorizeurl'] = isset($provider_se->authorization_endpoint) ? stripslashes($provider_se->authorization_endpoint) : "";
	                            $newapp['accesstokenurl'] = isset($provider_se->token_endpoint) ? stripslashes($provider_se->token_endpoint ) : "";
	                            $newapp['resourceownerdetailsurl'] = isset($provider_se->userinfo_endpoint) ? stripslashes($provider_se->userinfo_endpoint) : "";
	                            $newapp['discovery'] = $discovery_endpoint;
                        	}else{
				    $newapp['scope'] = isset($scope) ? $scope : '';
	                            $newapp['authorizeurl'] = "";
	                            $newapp['accesstokenurl'] = "";
	                            $newapp['resourceownerdetailsurl'] = "";
                        	}
                        }
                    } else {
                        update_option('mo_oc_valid_discovery_ep', true);
                        $newapp['authorizeurl'] = isset($_POST['mo_oauth_authorizeurl']) ? stripslashes(sanitize_text_field($_POST['mo_oauth_authorizeurl'])) : "";
                        $newapp['accesstokenurl'] = isset($_POST['mo_oauth_accesstokenurl']) ? stripslashes(sanitize_text_field($_POST['mo_oauth_accesstokenurl'])) : "";
                        $newapp['resourceownerdetailsurl'] = isset($_POST['mo_oauth_resourceownerdetailsurl']) ? stripslashes(sanitize_text_field($_POST['mo_oauth_resourceownerdetailsurl'])) : "";
                    }

					$appslist[$appname] = $newapp;
					update_option('mo_oauth_apps_list', $appslist);

					if( isset($_POST['mo_oauth_discovery']) && !$provider_se)
                    {
                        update_option( 'message', 'Error: Incorrect Domain/Tenant/Policy/Realm. Please configure with correct values and try again.' );
                        update_option( 'mo_discovery_validation', 'invalid');
                        $this->mo_oauth_show_error_message();
                    } else {
                        update_option('message', 'Your settings are saved successfully.');
                        update_option('mo_discovery_validation', 'valid');
                        $this->mo_oauth_show_success_message();
//                    }
                        if (!isset($newapp['username_attr']) || empty($newapp['username_attr']) && get_option('mo_oauth_apps_list') ) {
                            $notices = get_option('mo_oauth_client_notice_messages');
                            $notices['attr_mapp_notice'] = 'Please map the attributes by going to the <a href="' . admin_url('admin.php?page=mo_oauth_settings&tab=attributemapping') . '">Attribute/Role Mapping</a> Tab.';
                            update_option('mo_oauth_client_notice_messages', $notices);
                        }
                    }
				}
			}
		}
		else if( isset( $_POST['option'] ) and sanitize_text_field( wp_unslash( $_POST['option'] ) ) == "mo_oauth_app_customization" && isset( $_REQUEST['mo_oauth_app_customization_form_field'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_REQUEST['mo_oauth_app_customization_form_field'] ) ), 'mo_oauth_app_customization_form' )) {

			if( current_user_can( 'administrator' ) ) {
				update_option( 'mo_oauth_icon_width',  stripslashes(sanitize_text_field($_POST['mo_oauth_icon_width'])));
				update_option( 'mo_oauth_icon_height', stripslashes(sanitize_text_field($_POST['mo_oauth_icon_height'])));
				update_option( 'mo_oauth_icon_margin', stripslashes(sanitize_text_field($_POST['mo_oauth_icon_margin'])));
				update_option('mo_oauth_icon_configure_css', stripslashes(sanitize_text_field($_POST['mo_oauth_icon_configure_css'])));
				update_option( 'message', 'Your settings were saved' );
				$this->mo_oauth_show_success_message();
			}
		}
		else if( isset( $_POST['option'] ) and sanitize_text_field( wp_unslash( $_POST['option'] ) ) == "mo_oauth_attribute_mapping"  && isset( $_REQUEST['mo_oauth_attr_role_mapping_form_field'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_REQUEST['mo_oauth_attr_role_mapping_form_field'] ) ), 'mo_oauth_attr_role_mapping_form' )) {

			if( current_user_can( 'administrator' ) ) {
				$appname = isset($_POST['mo_oauth_app_name']) ? stripslashes( sanitize_text_field($_POST['mo_oauth_app_name']) ) : '';
				$username_attr = isset($_POST['mo_oauth_username_attr']) ? stripslashes( sanitize_text_field($_POST['mo_oauth_username_attr']) ) : '';
				$attr_option = isset($_POST['mo_attr_option']) ? stripslashes( sanitize_text_field($_POST['mo_attr_option']) ) : '';
				if ( empty( $appname ) ) {
					update_option( 'message', 'You MUST configure an application before you map attributes.' );
					$this->mo_oauth_show_error_message();
					return;
				}
				$appslist = get_option('mo_oauth_apps_list');
				foreach($appslist as $key => $currentapp){
					if($appname == $key){
						$currentapp['username_attr'] = $username_attr;
						$appslist[$key] = $currentapp;
						break;
					}
				}

				update_option('mo_oauth_apps_list', $appslist);
				update_option( 'message', 'Your settings are saved successfully.' );
				update_option('mo_attr_option', $attr_option);
				$this->mo_oauth_show_success_message();
				$notices = get_option( 'mo_oauth_client_notice_messages' );
				if( isset( $notices['attr_mapp_notice'] ) ) {
					unset( $notices['attr_mapp_notice'] );
					update_option( 'mo_oauth_client_notice_messages', $notices );
				}
			}
		}
		
		elseif( isset( $_POST['option'] ) and sanitize_text_field( wp_unslash( $_POST['option'] ) ) == "mo_oauth_contact_us_query_option" && isset( $_REQUEST['mo_oauth_support_form_field'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_REQUEST['mo_oauth_support_form_field'] ) ), 'mo_oauth_support_form' )) {

			if( current_user_can( 'administrator' ) ) {
				if( mooauth_is_curl_installed() == 0 ) {
					return $this->mo_oauth_show_curl_error();
				}
				// Contact Us query
				$email = sanitize_email( $_POST['mo_oauth_contact_us_email'] );
				$phone = stripslashes( sanitize_text_field($_POST['mo_oauth_contact_us_phone']) );
				$query = stripslashes( sanitize_text_field($_POST['mo_oauth_contact_us_query']) );
				$send_config = isset($_POST['mo_oauth_send_plugin_config']) ? sanitize_post($_POST['mo_oauth_send_plugin_config']) : "0";
				$customer = new MOOAuth_Client_Customer();
				if ( $this->mo_oauth_check_empty_or_null( $email ) || $this->mo_oauth_check_empty_or_null( $query ) ) {
					update_option('message', 'Please fill up Email and Query fields to submit your query.');
					$this->mo_oauth_show_error_message();
				} else {
					$mo_call_setup = array_key_exists('oauth_setup_call', $_POST);
					$mo_call_setup_validated = false;
					$issue_description= null;

					if($mo_call_setup === true){
						$issue = isset($_POST['mo_oauth_setup_call_issue']) ? sanitize_text_field($_POST['mo_oauth_setup_call_issue']) : ''; //select
						$call_date = isset($_POST['mo_oauth_setup_call_date']) ? sanitize_text_field($_POST['mo_oauth_setup_call_date']) : '';
						$issue_description = isset($_POST['mo_oauth_issue_description']) ? sanitize_text_field($_POST['mo_oauth_issue_description']) : '';
						$time_diff = isset($_POST['mo_oauth_time_diff']) ? sanitize_text_field($_POST['mo_oauth_time_diff']) : '';	//timezone offset
						$call_time = isset($_POST['mo_oauth_setup_call_time']) ? sanitize_text_field($_POST['mo_oauth_setup_call_time']) : ''; //time input

						if ( !($this->mo_oauth_check_empty_or_null( $email ) || $this->mo_oauth_check_empty_or_null( $issue ) || $this->mo_oauth_check_empty_or_null( $call_date ) || $this->mo_oauth_check_empty_or_null( $time_diff ) || $this->mo_oauth_check_empty_or_null( $call_time )) ) {
							// Please modify the $time_diff to test for the different timezones.
							// Note - $time_diff for IST is -330
							// $time_diff = 240;
							$hrs = floor(abs($time_diff)/60);
							$mins = fmod(abs($time_diff),60);
							if($mins == 0) {
								$mins = '00';
							}
							$sign = '+';
							if($time_diff > 0) {
								$sign = '-';
							}
							$call_time_zone = 'UTC '.$sign.' '.$hrs.':'.$mins;
							$call_date = date("jS F",strtotime($call_date));
							
							//code to convert local time to IST
							$local_hrs = explode(':', $call_time)[0];
							$local_mins = explode(':', $call_time)[1];
							$call_time_mins = ($local_hrs * 60) + $local_mins;
							$ist_time = $call_time_mins + $time_diff + 330;
							$ist_date = $call_date;
							if($ist_time > 1440) {
								$ist_time = fmod($ist_time,1440);
								$ist_date = date("jS F", strtotime("1 day", strtotime($call_date)));
							}
							else if($ist_time < 0) {
								$ist_time = 1440 + $ist_time;
								$ist_date = date("jS F", strtotime("-1 day", strtotime($call_date)));
							}
							$ist_hrs = floor($ist_time/60);
							$ist_hrs = sprintf("%02d", $ist_hrs);

							$ist_mins = fmod($ist_time,60);
							$ist_mins = sprintf("%02d", $ist_mins);
							
							$ist_time = $ist_hrs.':'.$ist_mins;
							 $mo_call_setup_validated = true;
						}
					}
					if ($mo_call_setup && $mo_call_setup_validated) {
						$submited = $customer->submit_setup_call( $email, $issue, $issue_description, $query, $call_date, $call_time_zone, $call_time, $ist_date, $ist_time, $phone, $send_config);
					}elseif($mo_call_setup || $mo_call_setup_validated){
						$submited = false;
					}
					else{
						$submited = $customer->submit_contact_us( $email, $phone, $query, $send_config );
					}
					
					if ( $submited == false ) {
						update_option('message', 'Your query could not be submitted. Please fill up all the required fields and try again.');
						$this->mo_oauth_show_error_message();
					} else {
						update_option('message', 'Thanks for getting in touch! We shall get back to you shortly.');
						$this->mo_oauth_show_success_message();
					}
				}
			}	
		} 
		elseif( isset( $_POST['option'] ) and sanitize_text_field( wp_unslash( $_POST['option'] ) ) == "mo_oauth_client_demo_request_form" && isset($_REQUEST['mo_oauth_client_demo_request_field']) && wp_verify_nonce(sanitize_text_field(wp_unslash($_REQUEST['mo_oauth_client_demo_request_field'])), 'mo_oauth_client_demo_request_form') ) {

			if( current_user_can( 'administrator' ) ) {
				if( mooauth_is_curl_installed() == 0 ) {
					return $this->mo_oauth_show_curl_error();
				}
				// Demo Request
				$email = sanitize_email( $_POST['mo_auto_create_demosite_email'] );
				$demo_plan = stripslashes( sanitize_text_field($_POST['mo_auto_create_demosite_demo_plan']) );
				$query = stripslashes( sanitize_text_field($_POST['mo_auto_create_demosite_usecase']) );

				if ( $this->mo_oauth_check_empty_or_null( $email ) || $this->mo_oauth_check_empty_or_null( $demo_plan ) || $this->mo_oauth_check_empty_or_null($query) ) {
					update_option('message', 'Please fill up Usecase, Email field and Requested demo plan to submit your query.');
					$this->mo_oauth_show_error_message();
				} else {

				$demosite_status = (bool) @fsockopen('demo.miniorange.com', 443, $iErrno, $sErrStr, 5);
				$addons = MOOAuth_Client_Admin_Addons::$all_addons;
				$addons_selected = '';
				foreach($addons as $key => $value){
					if(isset($_POST[$value['tag']]) && sanitize_text_field($_POST[$value['tag']]) == "true")
						$addons_selected.= $value['title'].", ";
				}
				$addons_selected = rtrim($addons_selected, ", ");
				if(empty($addons_selected) || is_null($addons_selected))
					$addons_selected = 'No Add-ons selected';
					if ( $demosite_status && "Not Sure" !==  $demo_plan ) {
						$url = 'https://demo.miniorange.com/wordpress-oauth/';
	
						$headers = array( 'Content-Type' => 'application/x-www-form-urlencoded', 'charset' => 'UTF - 8');
						$args = array(
							'method' =>'POST',
							'body' => array(
								'option' => 'mo_auto_create_demosite',
								'mo_auto_create_demosite_email' => $email,
								'mo_auto_create_demosite_usecase' => $query,
								'mo_auto_create_demosite_demo_plan' => $demo_plan,
								'mo_auto_create_demosite_plugin_name' => MO_OAUTH_PLUGIN_SLUG,
								'mo_auto_create_demosite_addons' => $addons_selected
							),
							'timeout' => '20',
							'redirection' => '5',
							'httpversion' => '1.0',
							'blocking' => true,
							'headers' => $headers,
	
						);
	
						$response = wp_remote_post( $url, $args );
	
						if ( is_wp_error( $response ) ) {
							$error_message = $response->get_error_message();
							echo "Something went wrong: ". esc_attr( $error_message );
							exit();
						}
						$output = wp_remote_retrieve_body($response);
						$output = json_decode($output);
	
						if(is_null($output)){
							$customer = new MOOAuth_Client_Customer();
							$customer->mo_oauth_send_demo_alert( $email, $demo_plan, $query,$addons_selected, "WP OAuth Client On Demo Request - ".$email );
							update_option('message', "Thanks Thanks for getting in touch! We shall get back to you shortly.");
							$this->mo_oauth_show_success_message();
						} else {
							if($output->status == 'SUCCESS'){
								update_option('message', $output->message);
								$this->mo_oauth_show_success_message();
							}else{
								update_option('message', $output->message);
								$this->mo_oauth_show_error_message();
							}
						}
					} else {
						$customer = new MOOAuth_Client_Customer();
						$customer->mo_oauth_send_demo_alert( $email, $demo_plan, $query,$addons_selected, "WP OAuth Client On Demo Request - ".$email );
						update_option('message', "Thanks for getting in touch! We shall get back to you shortly.");
						$this->mo_oauth_show_success_message();
					}
				}
			}
		}
		//
		elseif( isset( $_POST['option'] ) and sanitize_text_field( wp_unslash( $_POST['option'] ) ) == "mo_oauth_client_video_demo_request_form" && isset($_REQUEST['mo_oauth_client_video_demo_request_field']) && wp_verify_nonce(sanitize_text_field(wp_unslash($_REQUEST['mo_oauth_client_video_demo_request_field'])), 'mo_oauth_client_video_demo_request_form') ) {
			if( current_user_can( 'administrator' ) ) {
				if( mooauth_is_curl_installed() == 0 ) {
					return $this->mo_oauth_show_curl_error();
				}

				//video demo request
				$email = sanitize_email( $_POST['mo_oauth_video_demo_email'] );
				$call_date = isset($_POST['mo_oauth_video_demo_request_date']) ? sanitize_text_field($_POST['mo_oauth_video_demo_request_date']) : '';
				$time_diff = isset($_POST['mo_oauth_video_demo_time_diff']) ? sanitize_text_field($_POST['mo_oauth_video_demo_time_diff']) : '';	//timezone offset
				$call_time = isset($_POST['mo_oauth_video_demo_request_time']) ? sanitize_text_field($_POST['mo_oauth_video_demo_request_time']) : ''; //time input
				$query = stripslashes( sanitize_text_field($_POST['mo_oauth_video_demo_request_usecase_text']) );
				$customer = new MOOAuth_Client_Customer();

				if ( $this->mo_oauth_check_empty_or_null( $email ) || $this->mo_oauth_check_empty_or_null( $call_date ) || $this->mo_oauth_check_empty_or_null($query) || $this->mo_oauth_check_empty_or_null( $time_diff ) || $this->mo_oauth_check_empty_or_null( $call_time ) ) {
					update_option('message', 'Please fill up Usecase, Email field and Requested demo plan to submit your query.');
					$this->mo_oauth_show_error_message();
				}
				else{
					
					$mo_oauth_video_demo_request_validated = false;
					$email = sanitize_email( $_POST['mo_oauth_video_demo_email'] );
					$call_date = isset($_POST['mo_oauth_video_demo_request_date']) ? sanitize_text_field($_POST['mo_oauth_video_demo_request_date']) : '';
					$time_diff = isset($_POST['mo_oauth_video_demo_time_diff']) ? sanitize_text_field($_POST['mo_oauth_video_demo_time_diff']) : '';	//timezone offset
					$call_time = isset($_POST['mo_oauth_video_demo_request_time']) ? sanitize_text_field($_POST['mo_oauth_video_demo_request_time']) : ''; //time input
					$query = stripslashes( sanitize_text_field($_POST['mo_oauth_video_demo_request_usecase_text']) );
						
					if ( !($this->mo_oauth_check_empty_or_null( $email ) || $this->mo_oauth_check_empty_or_null( $query ) || $this->mo_oauth_check_empty_or_null( $call_date ) || $this->mo_oauth_check_empty_or_null( $time_diff ) || $this->mo_oauth_check_empty_or_null( $call_time )) ) {
						// Please modify the $time_diff to test for the different timezones.
						// Note - $time_diff for IST is -330
						// $time_diff = 240;
						$hrs = floor(abs($time_diff)/60);
							$mins = fmod(abs($time_diff),60);
							if($mins == 0) {
								$mins = '00';
							}
							$sign = '+';
							if($time_diff > 0) {
								$sign = '-';
							}
							$call_time_zone = 'UTC '.$sign.' '.$hrs.':'.$mins;
							$call_date = date("jS F",strtotime($call_date));
							
							//code to convert local time to IST
							$local_hrs = explode(':', $call_time)[0];
							$local_mins = explode(':', $call_time)[1];
							$call_time_mins = ($local_hrs * 60) + $local_mins;
							$ist_time = $call_time_mins + $time_diff + 330;
							$ist_date = $call_date;
							if($ist_time > 1440) {
								$ist_time = fmod($ist_time,1440);
								$ist_date = date("jS F", strtotime("1 day", strtotime($call_date)));
							}
							else if($ist_time < 0) {
								$ist_time = 1440 + $ist_time;
								$ist_date = date("jS F", strtotime("-1 day", strtotime($call_date)));
							}
							$ist_hrs = floor($ist_time/60);
							$ist_hrs = sprintf("%02d", $ist_hrs);

							$ist_mins = fmod($ist_time,60);
							$ist_mins = sprintf("%02d", $ist_mins);
							
							$ist_time = $ist_hrs.':'.$ist_mins;
							$mo_oauth_video_demo_request_validated = true;
					}


					if ($mo_oauth_video_demo_request_validated) {
						$customer->mo_oauth_send_video_demo_alert( $email, $ist_date, $query,$ist_time, "WP OAuth Client Video Demo Request - ".$email ,$call_time_zone,$call_time,$call_date);
						update_option('message', "Thanks for getting in touch! We shall get back to you shortly.");
						$this->mo_oauth_show_success_message();
					}
					else{
						update_option('message', 'Your query could not be submitted. Please fill up all the required fields and try again.');
						$this->mo_oauth_show_error_message();
					} 

				}
			}
		}
		//
        else if (isset($_POST ['option']) && sanitize_text_field( wp_unslash( $_POST['option'] ) ) == 'mo_oauth_forgot_password_form_option' && isset( $_REQUEST['mo_oauth_forgotpassword_form_field'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_REQUEST['mo_oauth_forgotpassword_form_field'] ) ), 'mo_oauth_forgotpassword_form' )) {

				if( current_user_can( 'administrator' ) ) {
					if (! mooauth_is_curl_installed()) {
						update_option('mo_oauth_message', 'ERROR: <a href="http://php.net/manual/en/curl.installation.php" target="_blank">PHP cURL extension</a> is not installed or disabled. Resend OTP failed.');
						$this->mo_oauth_show_error_message();
						return;
					}

					$email = get_option('mo_oauth_admin_email');

					$customer = new MOOAuth_Client_Customer();
					$content = json_decode($customer->mo_oauth_forgot_password($email), true);

					if (strcasecmp($content ['status'], 'SUCCESS') == 0) {
						update_option('message', 'Your password has been reset successfully. Please enter the new password sent to ' . $email . '.');
						$this->mo_oauth_show_success_message();
					}
				}
		} else if( isset( $_POST['option'] ) and sanitize_text_field( wp_unslash( $_POST['option'] ) ) == "mo_oauth_change_email"  && isset( $_REQUEST['mo_oauth_change_email_form_field'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_REQUEST['mo_oauth_change_email_form_field'] ) ), 'mo_oauth_change_email_form')) {
			//Adding back button
			update_option('mo_oauth_client_verify_customer', '');
			update_option('mo_oauth_client_registration_status','');
			update_option('mo_oauth_client_new_registration','true');
		}

		else if ( isset( $_POST['mo_oauth_client_feedback'] ) and sanitize_text_field( wp_unslash( $_POST['mo_oauth_client_feedback'] ) ) == 'true' && isset( $_REQUEST['mo_oauth_feedback_form_field'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_REQUEST['mo_oauth_feedback_form_field'] ) ), 'mo_oauth_feedback_form')) {
			
			if( current_user_can( 'administrator' ) ) {
				$user = wp_get_current_user();

				$message = 'Plugin Deactivated:';
				if( isset( $_POST[ 'deactivate_reason_select' ] )){
					$deactivate_reason = sanitize_text_field( wp_unslash($_POST['deactivate_reason_select']));
					$message .= ': '.$deactivate_reason;
				}
				
				$deactivate_reason_message = array_key_exists( 'query_feedback', $_POST ) ? sanitize_text_field( wp_unslash( $_POST['query_feedback'] ) ) : false;
				
				if ( isset( $deactivate_reason_message ) ) {
					$message .= ': ' . $deactivate_reason_message;
				}

				if(isset( $_POST[ 'rate' ] )){
				$rate_value = sanitize_text_field( htmlspecialchars($_POST['rate']));
				}

				$rating = "[Rating: ".$rate_value."]";

				$email = sanitize_text_field( wp_unslash($_POST[ 'query_mail' ] ) );
				if(!filter_var( $email, FILTER_VALIDATE_EMAIL )){
					$email = get_option( "mo_oauth_admin_email" );
				}

				$reply_required = '';
				if( isset( $_POST[ 'get_reply' ] ) )
					$reply_required = sanitize_text_field(htmlspecialchars($_POST['get_reply']));
					if(empty($reply_required)){
					$reply_required = "No";
					$reply ='[Reply :'.$reply_required.']';
				}else{
					$reply_required = "Yes";
					$reply ='[Reply :'.$reply_required.']';
				}
				$reply = $rating.' '.$reply;
								
				$feedback_reasons = new MOOAuth_Client_Customer();
				if(isset($_POST['miniorange_feedback_skip']) && sanitize_text_field( wp_unslash( $_POST['miniorange_feedback_skip'] ) ) == 'Skip'){
						deactivate_plugins( __FILE__ );
						if( !array_key_exists( 'mo_oauth_keep_settings_intact', $_POST ) ){
							$this->delete_options_on_deactivation();
						}
						update_option( 'message', 'Plugin deactivated successfully' );
						$this->mo_oauth_show_success_message();
				}
				else{
					if( $deactivate_reason && $email ){
						$submited = json_decode( $feedback_reasons->mo_oauth_send_email_alert( $email, $reply, $message, "Feedback: WordPress ".MO_OAUTH_PLUGIN_NAME ), true );
						deactivate_plugins( __FILE__ );
						if( !array_key_exists( 'mo_oauth_keep_settings_intact', $_POST ) ){
							$this->delete_options_on_deactivation();
						}
						update_option( 'message', 'Thank you for the feedback.' );
						$this->mo_oauth_show_success_message();
					}
					else if( empty( $deactivate_reason ) ){
						update_option( 'message', 'Please Select one of the reasons ,if your reason is not mentioned please select Other Reasons' );
						$this->mo_oauth_show_error_message();
					}
					else{
						update_option( 'message', 'Please enter your email address.' );
						$this->mo_oauth_show_error_message();
					}
				}
			}
		}


	}

	function mo_oauth_get_current_customer(){
		$customer = new MOOAuth_Client_Customer();
		$content = $customer->get_customer_key();
		$customerKey = json_decode( $content, true );
		if( json_last_error() == JSON_ERROR_NONE ) {
			update_option( 'mo_oauth_client_admin_customer_key', $customerKey['id'] );
			update_option( 'mo_oauth_client_admin_api_key', $customerKey['apiKey'] );
			update_option( 'mo_oauth_client_customer_token', $customerKey['token'] );
			update_option('password', '' );
			update_option( 'message', 'Customer retrieved successfully' );
			delete_option('mo_oauth_client_verify_customer');
			delete_option('mo_oauth_client_new_registration');
			$this->mo_oauth_show_success_message();
		} else {
			update_option( 'message', 'You already have an account with miniOrange. Please enter a valid password.');
			update_option('mo_oauth_client_verify_customer', 'true');
			$this->mo_oauth_show_error_message();

		}
	}

	function create_customer(){
		$customer = new MOOAuth_Client_Customer();
		$customerKey = json_decode( $customer->create_customer(), true );
		if( strcasecmp( $customerKey['status'], 'CUSTOMER_USERNAME_ALREADY_EXISTS') == 0 ) {
			$this->mo_oauth_get_current_customer();
			delete_option('mo_oauth_client_new_customer');
		} else if( strcasecmp( $customerKey['status'], 'SUCCESS' ) == 0 ) {
			update_option( 'mo_oauth_client_admin_customer_key', $customerKey['id'] );
			update_option( 'mo_oauth_client_admin_api_key', $customerKey['apiKey'] );
			update_option( 'mo_oauth_client_customer_token', $customerKey['token'] );
			update_option( 'password', '');
			update_option( 'message', 'Registered successfully.');
			update_option('mo_oauth_client_registration_status','MO_OAUTH_REGISTRATION_COMPLETE');
			update_option('mo_oauth_client_new_customer',1);
			delete_option('mo_oauth_client_verify_customer');
			delete_option('mo_oauth_client_new_registration');
			$this->mo_oauth_show_success_message();
		}
	}

	function mo_oauth_show_curl_error() {
		if( mooauth_is_curl_installed() == 0 ) {
			update_option( 'message', '<a href="http://php.net/manual/en/curl.installation.php" target="_blank">PHP CURL extension</a> is not installed or disabled. Please enable it to continue.');
			$this->mo_oauth_show_error_message();
			return;
		}
	}

	function mo_oauth_shortcode_login(){
		if(mooauth_migrate_customers() || !mooauth_is_customer_registered()) {
			return '<div class="mo_oauth_premium_option_text" style="text-align: center;border: 1px solid;margin: 5px;padding-top: 25px;"><p>This feature is supported only in standard and higher versions.</p>
				<p><a href="'.get_site_url(null, '/wp-admin/').'admin.php?page=mo_oauth_settings&tab=licensing">Click Here</a> to see our full list of Features.</p></div>';
		}
		$mowidget = new MOOAuth_Widget;
		return $mowidget->mo_oauth_login_form();
	}

	function mo_oauth_export_plugin_config( $share_with = false ) {
		$appslist = get_option('mo_oauth_apps_list');
		$currentapp_config = null;
		if ( is_array( $appslist ) ) {
			foreach( $appslist as $key => $value ) {
				$currentapp_config = $value;
				break;
			}
		}
		if ( $share_with ) {
			unset( $currentapp_config['clientid'] );
			unset( $currentapp_config['clientsecret'] );
		}
		return $currentapp_config;
	}

	function delete_options_on_deactivation(){
		$this->mo_oauth_deactivate();
		delete_option('mo_oauth_admin_email');
		delete_option('password');
		delete_option('mo_oauth_admin_fname');
		delete_option('mo_oauth_admin_lname');
		delete_option('mo_oauth_admin_company');
		if (get_option('mo_oauth_apps_list')){
			$appslist = get_option('mo_oauth_apps_list');
			foreach ($appslist as $key => $currentapp) {
				$name = $key;
				if( isset( $name )){
					delete_option('mo_oauth_' . $name . '_scope');
					delete_option('mo_oauth_' . $name . '_client_id');
					delete_option('mo_oauth_' . $name . '_client_secret');
				}
			}
		}
		delete_option('mo_oauth_apps_list');
		delete_option('mo_oauth_icon_width');
		delete_option('mo_oauth_icon_height');
		delete_option('mo_oauth_icon_margin');
		delete_option('mo_oauth_icon_configure_css');
		delete_option('mo_oauth_redirect_url');
		delete_option('mo_oauth_attr_name_list');
		delete_option('mo_oauth_authorizations');
		delete_option('mo_oauth_set_val');
		delete_option('mo_debug_enable');
		delete_option('mo_debug_check');
		delete_option('mo_oauth_do_activation_redirect');
		delete_option('mo_oauth_client_show_rest_api_message');
		delete_option('mo_oauth_setup_wizard_app');
		delete_option('mo_oauth_client_custom_token_endpoint_no_csecret');
		delete_option('mo_existing_app_flow');
		delete_option('mo_oauth_transactionId');
		delete_option('mo_oauth_message');
		delete_option('mo_debug_time');
		delete_option('mo_oauth_client_notice_messages');
		delete_option('mo_oauth_client_disable_authorization_header');
		delete_option('mo_attr_option');
		delete_option('mo_oc_valid_discovery_ep');
		delete_option('mo_discovery_validation');
		delete_option('mo_oauth_activation_time');
		delete_option('mo_oauth_login_icon_space');
		delete_option('mo_oauth_login_icon_custom_width');
		delete_option('mo_oauth_login_icon_custom_height');
		delete_option('mo_oauth_login_icon_custom_size');
		delete_option('mo_oauth_login_icon_custom_color');
		delete_option('mo_oauth_login_icon_custom_boundary');
	}

	function mo_oauth_upgrade_hook($mo_oauth_upgrader, $mo_oauth_parameters_received){
		$mo_oauth_activation_time = get_option('mo_oauth_activation_time');
		if($mo_oauth_activation_time === false){
			$activate_time = new DateTime();
			update_option('mo_oauth_activation_time', $activate_time);
		}

	}

}

	function mooauth_is_customer_registered() {
		$email 			= get_option('mo_oauth_admin_email');
		$customerKey 	= get_option('mo_oauth_client_admin_customer_key');
		if( ! $email || ! $customerKey || ! is_numeric( trim( $customerKey ) ) ) {
			return 0;
		} else {
			return 1;
		}
	}

	function mooauth_is_curl_installed() {
		if  (in_array  ('curl', get_loaded_extensions())) {
			return 1;
		} else {
			return 0;
		}
	}

new MOOAuth;
function mooauth_client_run() { $plugin = new MOOAuth_Client();$plugin->run();}
mooauth_client_run();
