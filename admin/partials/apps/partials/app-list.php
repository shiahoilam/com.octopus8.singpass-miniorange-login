<?php
require_once('defaultapps.php');
function mooauth_client_applist_page() {
	// tutorial();
	?>
	<style>
		.tableborder {
			border-collapse: collapse;
			width: 100%;
			border-color:#eee;
		}

		.tableborder th, .tableborder td {
			text-align: left;
			padding: 8px;
			border-color:#eee;
		}

		.tableborder tr:nth-child(even){background-color: #f2f2f2}
	</style>
	<div id="mo_oauth_app_list" class="mo_table_layout">
	<?php

		if(isset($_GET['action'])){
			switch(sanitize_text_field($_GET['action']))
			{				
				case 'delete':	
					if(isset($_GET['app'])) {
						$app = sanitize_text_field($_GET['app']);
						mooauth_client_delete_app($app);
						if ("CognitoApp" === $app) {
							?>
							<script>
								let url = window.location.href;
								url = url.split("&action=delete&app=CognitoApp")[0];
								window.location.replace(url);
							</script>
							<?php
							exit();
						}
					}
					mooauth_client_get_app_list();
					break;

				case 'instructions':
					if(isset($_GET['appId'])){
						MOOAuth_Client_Admin_Guides::instructions(sanitize_text_field($_GET['appId']));
					}
					mooauth_client_get_app_list();
					break;

				case 'discard':
					delete_option('mo_oauth_setup_wizard_app');
					delete_option('mo_oauth_apps_list');
					mooauth_client_get_app_list();					
					break;	

				case 'add':
					MOOAuth_Client_Admin_Apps::add_app();
					break;

				case 'update':
					if(isset($_GET['app']))
					MOOAuth_Client_Admin_Apps::update_app(sanitize_text_field($_GET['app']));
					break;			
			}
		}else{
			mooauth_client_get_app_list();
		} 
	 ?>
		</div>
	<?php
}

	function mooauth_client_get_app_list(){
		if(get_option('mo_oauth_apps_list') || get_option('mo_oauth_setup_wizard_app'))
			{
			$appslist = get_option('mo_oauth_apps_list');
			if((is_array($appslist) && sizeof($appslist)>0) || get_option('mo_oauth_setup_wizard_app'))
				echo "<br><a href='#'><button disabled style='float:right'>Add Application</button></a>";
			else
				echo "<br><a href='admin.php?page=mo_oauth_settings&action=add'><button style='float:right'>".esc_html__('Add Application','miniorange-login-with-eve-online-google-facebook')."</button></a>";
			echo "<h3>".esc_html__('Applications List','miniorange-login-with-eve-online-google-facebook')."</h3>";
			if(is_array($appslist) && sizeof($appslist)>0)
				echo "<p style='color:#a94442;background-color:#f2dede;border-color:#ebccd1;border-radius:5px;padding:12px'>".esc_html__('You can only add 1 application with free version. Upgrade to','miniorange-login-with-eve-online-google-facebook')." <a href='admin.php?page=mo_oauth_settings&tab=licensing'><b>enterprise</b></a> ".esc_html__('to add more.','miniorange-login-with-eve-online-google-facebook')."</p>";
			echo "<table class='tableborder'>";
			echo "<tr><th>".esc_html__('Name','miniorange-login-with-eve-online-google-facebook')."</th><th>".esc_html__('Action','miniorange-login-with-eve-online-google-facebook')."</th></tr>";
			if(get_option('mo_oauth_setup_wizard_app')){
				$app = json_decode(get_option('mo_oauth_setup_wizard_app'));
				echo "<tr><td>".esc_html($app->mo_oauth_app_name)." (".esc_html($app->mo_oauth_type).") </td><td><a href='".esc_attr( admin_url( 'admin.php?option=mo_oauth_client_setup_wizard' ) )."'>".esc_html__('Continue Setup','miniorange-login-with-eve-online-google-facebook')."</a> &nbsp <p style='display:inline;color:#a94442;'>(Your application setup is not yet completed)</p> | <a href='admin.php?page=mo_oauth_settings&tab=config&action=discard'>".esc_html__('Discard Draft','miniorange-login-with-eve-online-google-facebook')."</a></td><tr>";
			}
			else
				foreach($appslist as $key => $app){
					$currentapp=$app;
					echo "<tr><td>".esc_html($key), " (", esc_html($currentapp['apptype']), ") "."</td><td><a href='admin.php?page=mo_oauth_settings&tab=config&action=update&app=".esc_attr($key)."'>".esc_html__('Edit Application','miniorange-login-with-eve-online-google-facebook')."</a> | <a href='admin.php?page=mo_oauth_settings&tab=attributemapping&app=".esc_attr($key)."#attribute-mapping'>".esc_html__('Attribute Mapping','miniorange-login-with-eve-online-google-facebook')."</a> | <a href='admin.php?page=mo_oauth_settings&tab=attributemapping&app=".esc_attr($key)."#role-mapping'>".esc_html__('Role Mapping','miniorange-login-with-eve-online-google-facebook')."</a> | <a onclick='return confirm(\"Are you sure you want to delete this item?\")' href='admin.php?page=mo_oauth_settings&tab=config&action=delete&app=".esc_attr($key)."'>".esc_html__('Delete','miniorange-login-with-eve-online-google-facebook')."</a> | ";
					if(isset($_GET['action'])) {
						if('instructions' == sanitize_text_field($_GET['action'] )) {
						echo "<a href='admin.php?page=mo_oauth_settings&tab=config'>".esc_html__('Hide Instructions','miniorange-login-with-eve-online-google-facebook')."</a></td></tr>";
						}
					} else {
						echo "<a href='admin.php?page=mo_oauth_settings&tab=config&action=instructions&appId=".((isset($app['appId']) ? esc_attr($app['appId']) : ''))."'>".esc_html__('How to Configure?','miniorange-login-with-eve-online-google-facebook')."</a></td></tr>";
					}

			}
			echo "</table>";
			echo "<br><br>";

		} else {
			if(get_option('mo_oauth_setup_wizard_app')){
				$app = json_decode(get_option('mo_oauth_setup_wizard_app'));
			echo '';
			}else{
				echo '<center><div style="margin:5% 5% 5% 5%;">
					<h4>
						Add new client application to implement Single Sign On into your website
					</h4>
	                <button class="button button-primary button-large" id="mo-oauth-continue-setup">Add New Application</button>
                </div><center>
                <script>
                	jQuery("#mo-oauth-continue-setup").click(function(){
                		window.location.href = "'.esc_attr(admin_url( 'admin.php?option=mo_oauth_client_setup_wizard' )).'";
                	});
                </script>';
				// MOOAuth_Client_Admin_Apps::add_app();
			}
		}
	}

	function mooauth_client_delete_app($appname){
		$appslist = get_option('mo_oauth_apps_list');
		if(! is_array($appslist) || empty($appslist)) {
			return;
		}
		foreach($appslist as $key => $app){
			if($appname == $key){
				if( $appslist[$appname]['appId'] == 'wso2' )
					delete_option( 'mo_oauth_client_custom_token_endpoint_no_csecret' );
				unset($appslist[$key]);
				delete_option( 'mo_oauth_client_disable_authorization_header' );
				delete_option( 'mo_oauth_attr_name_list' );
				delete_option('mo_oauth_apps_list');
				$notices = get_option( 'mo_oauth_client_notice_messages' );
				if( isset( $notices['attr_mapp_notice'] ) ) {
					unset( $notices['attr_mapp_notice'] );
					update_option( 'mo_oauth_client_notice_messages', $notices );
				}
			}
		}
		update_option('mo_oauth_apps_list', $appslist);
		?>
		<script>
			window.location.href = "<?php echo esc_attr(admin_url( 'admin.php?page=mo_oauth_settings&tab=config' )); ?>";
		</script>
		<?php
	}
