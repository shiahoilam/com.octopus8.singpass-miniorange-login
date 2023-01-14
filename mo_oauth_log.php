<?php

class MOOAuth_Debug{

	public static function mo_oauth_log ( $mo_message ) {	
		$mo_pluginlog = plugin_dir_path(__FILE__).get_option('mo_oauth_debug').'.log';
		$mo_time = time();
		$mo_log = '[' . date( "Y-m-d H:i:s", $mo_time ) . ' UTC] : ' . print_r( $mo_message, true ) . PHP_EOL;
		if ( get_option( 'mo_debug_enable' ) ) {
            if ( get_option( 'mo_debug_check' ) ) {
                $mo_message = 'This is miniOrange OAuth plugin Debug Log file';
                error_log( $mo_message.PHP_EOL, 3, $mo_pluginlog );
            }
            else {
                error_log( $mo_log, 3, $mo_pluginlog );
            }
        }      
	}
}