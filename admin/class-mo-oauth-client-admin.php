<?php

require('partials'.DIRECTORY_SEPARATOR.'class-mo-oauth-client-admin-menu.php');

class MOOAuth_Client_Admin {

	
	private $plugin_name;
	private $version;

	public function __construct( $plugin_name, $version ) {
		$this->plugin_name = $plugin_name;
		$this->version = $version;
		$mo_path = (dirname(dirname(plugin_basename(__FILE__))));
		$mo_path = $mo_path.DIRECTORY_SEPARATOR.'mo_oauth_settings.php';
		add_filter( 'plugin_action_links_' . $mo_path, array( $this, 'add_action_links') );
	}

	//Function to add the Premium settings in Plugin's section

    function add_action_links ( $actions ) {

		$url = esc_url( add_query_arg(
		 'page',
		 'mo_oauth_settings',
		 get_admin_url() . 'admin.php'
	 ) );	
		$url.='&tab=config';
		$url2 =  $url.'&tab=licensing';
		$settings_link = "<a href='$url'>" . 'Configure' . '</a>';
//		$settings_link2 = "<a href='$url2' style=><b>" . 'Upgrade to Premium' . '</b></a>';
//		array_push($actions, $settings_link2);
		array_push($actions, $settings_link);
		return array_reverse($actions);
 }

	/**
	 * Register the stylesheets for the admin area.
	 *
	 */
	public function enqueue_styles() {
		if(isset($_REQUEST['tab']) && $_REQUEST['tab'] == 'licensing'){
            wp_enqueue_style( 'mo_oauth_bootstrap_css', plugins_url( 'css/bootstrap/bootstrap.min.css', __FILE__ ) );
            wp_enqueue_style('mo_oauth_license_page_style', plugins_url( 'css/mo-oauth-licensing.css', __FILE__ ) );
        }

	}

	/**
	 * Register the JavaScript for the admin area.
	 */
	public function enqueue_scripts() {
		if(isset($_REQUEST['tab']) && $_REQUEST['tab'] == 'licensing'){
            wp_enqueue_script( 'mo_oauth_modernizr_script', plugins_url( 'js/modernizr.js', __FILE__ ) );
            wp_enqueue_script( 'mo_oauth_popover_script', plugins_url( 'js/bootstrap/popper.min.js', __FILE__ ) );
            wp_enqueue_script( 'mo_oauth_bootstrap_script', plugins_url( 'js/bootstrap/bootstrap.min.js', __FILE__ ) );
        }
	}

	public function admin_menu() {

		$page = add_menu_page( 'SingPass MO OAuth Settings ' . esc_html__( 'Configure OAuth', 'mo_oauth_settings' ), MO_OAUTH_ADMIN_MENU, 'administrator', 'mo_oauth_settings', array( $this, 'menu_options' ) ,plugin_dir_url(__FILE__) . 'images/miniorange.png');

		global $submenu;
		if(is_array($submenu) && isset($submenu['mo_oauth_settings'])){
			$submenu['mo_oauth_settings'][0][0] = esc_html__( 'Configure OAuth', 'mo_oauth_login' );
		}	
	}
		
	function menu_options () {
		global $wpdb;
		update_option( 'host_name', 'https://login.xecurify.com' );
		$customerRegistered = mooauth_is_customer_registered();
		mooauth_client_main_menu();
	}
}
