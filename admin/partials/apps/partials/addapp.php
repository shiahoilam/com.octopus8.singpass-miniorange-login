<?php

	require('defaultapps.php');
	require('grant-settings.php');

	function mooauth_client_add_app_page(){
		$appslist = get_option('mo_oauth_apps_list');
		if ( is_array($appslist) && sizeof($appslist)>0 ) {
			echo "<p style='color:#a94442;background-color:#f2dede;border-color:#ebccd1;border-radius:5px;padding:12px'>You can only add 1 application with free version. Upgrade to <a href='admin.php?page=mo_oauth_settings&tab=licensing'><b>enterprise</b></a> to add more.</p>";
			exit;
		}
		?>
		<div id="toggle2" class="mo_panel_toggle">
			<h3><?php esc_html_e( 'Add Application', 'miniorange-login-with-eve-online-google-facebook' ); ?>
			  <span style="float:right">
		        <?php
				if ( isset( $_GET['appId'] ) ) {
		        	$currentAppId = sanitize_text_field( wp_unslash( $_GET['appId'] ) );
				    $currentapp = mooauth_client_get_app($currentAppId);
				    if ( $currentapp ) {
				    	$refAppId = array("other", "openidconnect");
					    $tempappname = !in_array($currentapp->appId, $refAppId) ? $currentapp->appId : "customApp";
					    $app = mooauth_client_get_app($tempappname);
		                if ( isset( $app->video ) ) { 
			                ?> 
			                <a href="<?php echo esc_attr( $app->video ); ?>" target="_blank" rel="noopener" class="mo-oauth-setup-video-button" style="text-decoration: none;" >Video Guide</a> 
			                <?php
						}
						if ( isset( $app->guide ) ) { 
							?> <a href="<?php echo esc_attr( $app->guide ); ?>" target="_blank" rel="noopener" class="mo-oauth-setup-guide-button" style="text-decoration: none;" > Setup Guide </a>
							<?php
						}
				    }
		        }
	            ?>
	           </span>
	         </h3>
			<form name="f" method="post" id="show_pointers">
				<?php wp_nonce_field('mo_oauth_clear_pointers_form','mo_oauth_clear_pointers_form_field'); ?>
	        	<input type="hidden" name="option" value="clear_pointers"/>
			</form>
		</div>

		<?php
		// Select from default apps
		if ( ! isset($_GET['appId'] ) ) {
			mooauth_client_show_default_apps();
		} else {

			$currentAppId = sanitize_text_field($_GET['appId']);
			$currentapp = mooauth_client_get_app($currentAppId);
			if ( $currentapp ) {
	            $refAppId = array("other", "openidconnect");
	            $tempappname = !in_array($currentapp->appId, $refAppId) ? $currentapp->appId : "customApp";

	            ?>
				<div id="mo_oauth_add_app">
				<form id="form-common" name="form-common" method="post" action="admin.php?page=mo_oauth_settings&tab=config&action=update&app=<?php echo esc_attr( $tempappname );?>" >
				<?php wp_nonce_field('mo_oauth_add_app_form','mo_oauth_add_app_form_field'); ?>
				<input type="hidden" name="option" value="mo_oauth_add_app" />
				<table class="mo_settings_table">
					<tr>
					<td><strong><font color="#FF0000">*</font><?php esc_html_e('Application:','miniorange-login-with-eve-online-google-facebook')?><br><br></strong></td>
					<td>
						<input type="hidden" name="mo_oauth_app_name" value="<?php echo esc_attr($currentAppId);?>">
						<input type="hidden" name="mo_oauth_app_type" value="<?php echo esc_attr($currentapp->type);?>">
						<?php echo esc_attr($currentapp->label);?> &nbsp;&nbsp;&nbsp;&nbsp; <a style="text-decoration:none" href ="admin.php?page=mo_oauth_settings"><div style="display:inline;background-color:#0085ba;color:#fff;padding:4px 8px;border-radius:4px"><?php esc_html_e('Change Application','miniorange-login-with-eve-online-google-facebook');?></div></a><br><br>
					</td>
					</tr>
					<tr><td><strong><?php esc_html_e('Redirect / Callback URL: ','miniorange-login-with-eve-online-google-facebook')?></strong><br>&emsp;<font><small><?php esc_html_e('Editable in ','miniorange-login-with-eve-online-google-facebook')?><a href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank" rel="noopener noreferrer">[STANDARD]</a></small></font></td>
					<td><input class="mo_table_textbox" id="callbackurl"  type="text"
                               name="mo_oauth_callback_url" value='<?php echo esc_attr( site_url() )."";?>'>
					&nbsp;&nbsp;
					<div class="tooltip" style="display: inline;"><span class="tooltiptext" id="moTooltip">Copy to clipboard</span><i class="fa fa-clipboard fa-border" style="font-size:20px; align-items: center;vertical-align: middle;" aria-hidden="true" onclick="mooauth_copyUrl()" onmouseout="mooauth_outFunc()"></i></div>
					</td>
					</tr>
					
					<tr id="mo_oauth_custom_app_name_div">
						<td><strong><font color="#FF0000">*</font><?php esc_html_e('App Name','miniorange-login-with-eve-online-google-facebook')?> (<?php printf(esc_html__('%s','miniorange-login-with-eve-online-google-facebook'),esc_html( $currentapp->type) );?>):</strong></td>
						<td><input class="mo_table_textbox" onkeyup="mooauth_updateFormAction()" type="text" id="mo_oauth_custom_app_name" name="mo_oauth_custom_app_name" value="<?php echo esc_attr( $tempappname ); ?>" pattern="^[a-zA-Z0-9]+( [a-zA-Z0-9\s]+)*$" required title="Please do not add any special characters." placeholder="Do not add any special characters" maxlength="14"></td>
					</tr>
		<!--			<tr id="mo_oauth_display_app_name_div">-->
		<!--				<td><strong>Display App Name:</strong><br>&emsp;<font color="#FF0000"><small><a href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank" rel="noopener noreferrer">[STANDARD]</a></small></font></td>-->
		<!--				<td><input class="mo_table_textbox" type="text" id="mo_oauth_display_app_name" name="mo_oauth_display_app_name" value="Login with <App Name>" pattern="[a-zA-Z0-9\s]+" disabled title="Please do not add any special characters."></td>-->
		<!--			</tr>-->
				</table>
				
				<table class="mo_settings_table" id="mo_oauth_client_creds">
					<tr>
						<td><strong><font color="#FF0000">*</font><?php esc_html_e('Client ID:','miniorange-login-with-eve-online-google-facebook')?></strong></td>
						<td><input id="mo_oauth_client_id" class="mo_table_textbox" required="" type="text" name="mo_oauth_client_id" value=""></td>
					</tr>
					<tr>
						<td><strong><font color="#FF0000">*</font><?php esc_html_e('Client Secret:','miniorange-login-with-eve-online-google-facebook')?></strong></td>
						<td>
							<input id="mo_oauth_client_secret" class="mo_table_textbox" required="" type="password"  name="mo_oauth_client_secret" value="">
							
							<i class="fa fa-eye" onclick="mooauth_showClientSecret()" id="show_button" style="margin-left:-30px; cursor:pointer;"></i>
						</td>

					</tr>

				</table>
				
					<?php
				if ( isset($currentapp->discovery ) && $currentapp->discovery !="") { ?>
				<table class="mo_settings_table">
		                <tr>
		                    <td><input type="hidden" id="mo_oauth_discovery" name="mo_oauth_discovery" value="<?php if ( isset($currentapp->discovery ) ) echo esc_html($currentapp->discovery);?>"></td>
		                </tr>
		           <?php if ( isset( $currentapp->domain ) ) { ?>
		            <tr>
		                <td><strong><font color="#FF0000">*</font><?php printf( esc_html__( '%s', 'miniorange-login-with-eve-online-google-facebook') , esc_html( $currentapp->label ) );?> <?php esc_html_e('Domain:','miniorange-login-with-eve-online-google-facebook')?></strong></td>
		                <td><input class="mo_table_textbox" <?php if(isset($currentapp->domain)) echo 'required';?> type="text" id="mo_oauth_provider_domain" name="mo_oauth_provider_domain" placeholder= "<?php if(isset($currentapp->domain)) echo "Ex. ". esc_attr($currentapp->domain);?>" value=""></td>
		            </tr>

		                <?php } elseif(isset($currentapp->tenant)) { ?>
		                    <tr>
		                        <td><strong><font color="#FF0000">*</font><?php printf( esc_html__('%s','miniorange-login-with-eve-online-google-facebook'), esc_html($currentapp->label) ); ?><?php esc_html_e(' Tenant:','miniorange-login-with-eve-online-google-facebook')?></strong></td>
		                        <td><input class="mo_table_textbox" <?php if(isset($currentapp->tenant)) echo 'required';?> type="text" id="mo_oauth_provider_tenant" name="mo_oauth_provider_tenant" placeholder= "<?php if(isset($currentapp->tenant)); echo esc_html($currentapp->tenant); ?>" value=""></td>
		                    </tr>
		            <?php } if(isset($currentapp->policy)) { ?>
		            <tr>
		                <td><strong><font color="#FF0000">*</font><?php printf( esc_html__('%s','miniorange-login-with-eve-online-google-facebook'), esc_html($currentapp->label)); ?> <?php esc_html_e('Policy:','miniorange-login-with-eve-online-google-facebook')?></strong></td>
		                <td><input class="mo_table_textbox" <?php if(isset($currentapp->policy)) echo 'required';?> type="text" id="mo_oauth_provider_policy" name="mo_oauth_provider_policy" placeholder= "<?php if(isset($currentapp->policy)) echo "Ex. ". esc_html($currentapp->policy);?>" value=""></td>
		            </tr>
		            <?php } elseif(isset($currentapp->realmname)) { ?>
		                    <tr>
		                        <td><strong><font color="#FF0000">*</font><?php printf( esc_html__('%s','miniorange-login-with-eve-online-google-facebook'), esc_html($currentapp->label)); ?> <?php esc_html_e('Realm:','miniorange-login-with-eve-online-google-facebook')?></strong></td>
		                        <td><input class="mo_table_textbox" <?php if(isset($currentapp->realmname)) echo 'required';?> type="text" id="mo_oauth_provider_realm" name="mo_oauth_provider_realm" placeholder= "Add a name of a realm" value=""></td>
		                    </tr>
				</table>
		                <?php }
		            } ?>
				<table class="mo_settings_table" id="mo_oauth_client_endpoints">
		            <?php if(!isset($currentapp->discovery) || $currentapp->discovery =="") {
		            		if($currentapp->type != 'oauth1'){
		            	?>
		                <tr>
		                    <td><strong><?php esc_html_e('Scope:','miniorange-login-with-eve-online-google-facebook')?></strong></td>
		                    <td><input class="mo_table_textbox" type="text" name="mo_oauth_scope" value="<?php if(isset($currentapp->scope)) echo esc_attr($currentapp->scope);?>"></td>
		                </tr>
		                <?php } ?>
					<tr id="mo_oauth_authorizeurl_div">
						<?php if($currentapp->type == 'oauth1'){  ?>
						<tr>
		                	<td><strong><font color="#FF0000">*</font><?php esc_html_e('Request Token Endpoint:','miniorange-login-with-eve-online-google-facebook')?></strong></td>
		                	<td><input class="mo_table_textbox" id="mo_oauth_requesturl"  name="mo_oauth_requesturl" required="" type="text"  value="<?php if(isset($currentapp->requesturl)) echo esc_attr($currentapp->requesturl);?>"></td>
		              
		                </tr>
		            <?php }?>
						<td><strong><font color="#FF0000">*</font><?php esc_html_e('Authorize Endpoint:','miniorange-login-with-eve-online-google-facebook')?></strong></td>
						<td><input class="mo_table_textbox" <?php if(!isset($currentapp->discovery) || $currentapp->discovery=="") echo 'required';?> type="text" id="mo_oauth_authorizeurl" name="mo_oauth_authorizeurl" value="<?php if(isset($currentapp->authorize)) echo esc_attr($currentapp->authorize);?>"></td>
					</tr>
					<tr id="mo_oauth_accesstokenurl_div">
						<td><strong><font color="#FF0000">*</font><?php esc_html_e('Access Token Endpoint:','miniorange-login-with-eve-online-google-facebook')?></strong></td>
						<td><input class="mo_table_textbox" <?php if(!isset($currentapp->discovery) || $currentapp->discovery=="") echo 'required';?> type="text" id="mo_oauth_accesstokenurl" name="mo_oauth_accesstokenurl" value="<?php if(isset($currentapp->token)) echo esc_attr($currentapp->token);?>"></td>
					</tr>
					<?php if(!isset($currentapp->type) || $currentapp->type=='oauth' || $currentapp->type=='oauth1') {?>
						<tr id="mo_oauth_resourceownerdetailsurl_div">
							<td><strong><font color="#FF0000">*</font><?php esc_html_e('Get User Info Endpoint:','miniorange-login-with-eve-online-google-facebook')?></strong></td>
							<td><input class="mo_table_textbox" <?php if(!isset($currentapp->type) || $currentapp->type=='oauth' || !isset($currentapp->discovery) || $currentapp->discovery=="" ) echo 'required';?> type="text" id="mo_oauth_resourceownerdetailsurl" name="mo_oauth_resourceownerdetailsurl" value="<?php if(isset($currentapp->userinfo)) echo esc_attr($currentapp->userinfo);?>"></td>
						</tr>
					<?php } 
		        	 } 
		        	if($currentapp->type!='oauth1'){
		        	?>
		            <tr>
		                <td><strong><?php esc_html_e('Send client credentials in:','miniorange-login-with-eve-online-google-facebook')?></strong></td>
		                <td><div style="padding:5px;"></div><input type="checkbox" name="mo_oauth_authorization_header" value ="1" checked /> Header<span style="padding:0px 0px 0px 8px;"></span><input type="checkbox" name="mo_oauth_body" value ="0"/> Body<div style="padding:5px;"></div></td>
		            </tr>

		        	<tr>
						<td><strong><?php esc_html_e('State Parameter :','miniorange-login-with-eve-online-google-facebook')?></strong></td>
						<td><div style="padding:5px;"></div><input type="checkbox" name="mo_oauth_state" value ="1" <?php if(isset($currentapp->send_state)) { if($currentapp->send_state === 1 ){ echo 'checked';}else{$currentapp->send_state=1;echo 'checked';} } ; ?> checked/><?php esc_html_e('Send state parameter','miniorange-login-with-eve-online-google-facebook')?></td>
						<td><br></td>
					</tr>
					<?php } ?>
					<tr>
						<td><strong><?php esc_html_e('login button:','miniorange-login-with-eve-online-google-facebook')?></strong></td>
						<td><div style="padding:5px;"></div><input type="checkbox" name="mo_oauth_show_on_login_page" value ="1" checked/><?php esc_html_e('Show on login page','miniorange-login-with-eve-online-google-facebook')?></td>
					</tr>
					<tr>
						<td><br></td>
						<td><br></td>
					</tr>
					</table>
					<table class="mo_settings_table">
						<tr>
							<td>&nbsp;</td>
							<td><input id="mo_save_app" type="submit" name="submit_save_app" value="<?php esc_html_e('Save settings','miniorange-login-with-eve-online-google-facebook'); ?>"
								class="button button-primary button-large" /></td>
						</tr>
					</table>
				</form>

				<div id="instructions">

				</div>
				</div>

			
				<?php
				mooauth_client_grant_type_settings();
			}
		}
	}
