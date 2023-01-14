<?php


function mooauth_client_attribite_role_mapping_ui(){
	$appslist = get_option('mo_oauth_apps_list');
	$attr_name_list = get_option('mo_oauth_attr_name_list');
	
	if ( false !== $attr_name_list ) {
		$temp = [];
		$attr_name_list = mooauth_client_dropdownattrmapping('', $attr_name_list, $temp );
	}
	$currentapp = null;
	$currentappname = null;
	if ( is_array( $appslist ) ) {
		foreach( $appslist as $key => $value ) {
			$currentapp = $value;
			$currentappname = $key;
			break;
		}
	}
	//Attribute mapping
	?>
	<div class="mo_table_layout" id="attribute-mapping">
		<form id="form-common" name="form-common" method="post" action="admin.php?page=mo_oauth_settings&tab=attributemapping">
			<?php wp_nonce_field('mo_oauth_attr_role_mapping_form','mo_oauth_attr_role_mapping_form_field'); ?>
		<h3><?php esc_html_e('Attribute Mapping ','miniorange-login-with-eve-online-google-facebook')?><small>[<?php esc_html_e('required for SSO & ACCOUNT LINKING ','miniorange-login-with-eve-online-google-facebook')?></small>]</h3> 
		<p style="font-size:13px;color:#dc2424"><?php wp_nonce_field('mo_oauth_attr_role_mapping_form','mo_oauth_attr_role_mapping_form_field'); ?><?php esc_html_e('Do ','miniorange-login-with-eve-online-google-facebook')?><b><?php esc_html_e('Test Configuration','miniorange-login-with-eve-online-google-facebook')?></b><?php esc_html_e(' to get configuration for attribute mapping.','miniorange-login-with-eve-online-google-facebook')?><br></p>
		<input type="hidden" name="option" value="mo_oauth_attribute_mapping" />
		<input class="mo_table_textbox" required="" type="hidden" id="mo_oauth_app_name" name="mo_oauth_app_name" value="<?php echo esc_attr($currentappname);?>">
		<input class="mo_table_textbox" required="" type="hidden" name="mo_oauth_custom_app_name" value="<?php echo esc_attr($currentappname);?>">
		<table class="mo_settings_table">
			<tr id="mo_oauth_email_attr_div">
				<td><strong><font color="#FF0000">*</font><?php esc_html_e('Username:','miniorange-login-with-eve-online-google-facebook')?></strong></td>
				<td>
					<?php
					if( is_array( $attr_name_list ) ) {  ?>
						<select class="mo_table_textbox" <?php if (get_option('mo_attr_option') === "manual" ) echo 'style="display:none"'; ?> id="mo_oauth_username_attr_select" <?php if ( get_option('mo_attr_option') === false || get_option('mo_attr_option') === "automatic" ) echo 'name="mo_oauth_username_attr"'; ?> >
						<option value="">----------- Select an Attribute -----------</option>
							<?php 
							foreach ( $attr_name_list as $key => $value ) {
								echo "<option value='" . esc_attr( $value ) . "'";
								if( ( isset( $currentapp['username_attr'] ) && $currentapp['username_attr'] === $value ) ||  ( isset( $currentapp['email_attr'] ) && $currentapp['email_attr'] === $value ) ) {
									echo " selected";
								}
								else echo "";
								echo " >".esc_attr($value)."</option>";
							}
							?>
						</select>
						<script>
						function mooauth_changeFormField(){
							var select_box = document.getElementById('mo_oauth_username_attr_select');
							var input_tag = document.getElementById('mo_oauth_username_attr_input');
							if (select_box.style.display != "none") {
								select_box.name = "";
								select_box.style.display = "none";
								input_tag.name = "mo_oauth_username_attr";
								input_tag.style.display = "block";
								document.getElementById('mo_username_attr_change_p').innerHTML = "Change to automatic mode";
								document.getElementById('mo_attr_option').value = "manual";
							} else {
								select_box.name = "mo_oauth_username_attr";
								select_box.style.display = "block";
								input_tag.name = "";
								input_tag.style.display = "none";
								document.getElementById('mo_username_attr_change_p').innerHTML = "Change to manual mode";
								document.getElementById('mo_attr_option').value = "automatic";
							}
						}
						</script>
						<input type="hidden" id="mo_attr_option" name="mo_attr_option" value="<?php if(get_option('mo_attr_option')){ echo esc_attr( get_option('mo_attr_option') ); } else { echo "automatic"; } ?>">
						<input <?php if (get_option('mo_attr_option') === "manual" ) echo 'name="mo_oauth_username_attr"'; ?> class="mo_table_textbox" <?php if (get_option('mo_attr_option') === "automatic" || get_option('mo_attr_option') === false ) echo 'style="display:none"'; ?> placeholder="Enter attribute name for Username" type="text" id="mo_oauth_username_attr_input" value="<?php if( isset( $currentapp['username_attr'] ) )echo esc_attr($currentapp['username_attr']); else if( isset( $currentapp['email_attr'] ) )echo esc_attr($currentapp['email_attr']);?>">
						</td>
						<?php $text_attr = get_option('mo_attr_option') ? get_option('mo_attr_option') === "manual" ? "Change to automatic mode" : "Change to manual mode" : "Change to manual mode"; ?>
						<td>
							<a href="#" id="mo_username_attr_change_p" onclick="mooauth_changeFormField()"><?php echo esc_html_e($text_attr,'miniorange-login-with-eve-online-google-facebook'); ?></a>
						</td>
						<?php
					} else { ?>
						<input class="mo_table_textbox" required="" placeholder="Enter attribute name for Username" type="text" id="mo_oauth_username_attr_input" name="mo_oauth_username_attr" value="<?php if( isset( $currentapp['username_attr'] ) )echo esc_attr($currentapp['username_attr']); else if( isset( $currentapp['email_attr'] ) )echo esc_attr($currentapp['email_attr']);?>">
						</td>
						<td>
						</td>
						<?php
					}
					?>
			</tr>
			
			
			
		<?php
		echo '<tr>
			<td></td><td>
            <b><p style="margin-left:2px" class=" mop_table">'.esc_html__('Advanced attribute mapping is available in','miniorange-login-with-eve-online-google-facebook').'
			<a href="admin.php?page=mo_oauth_settings&amp;tab=licensing">premium</a> version.</b><br>
			<a href="https://developers.miniorange.com/docs/oauth/wordpress/client/attribute-role-mapping" target="_blank">['.esc_html__('How to map Attributes?','miniorange-login-with-eve-online-google-facebook').']</a>
            </p>
			</td>
		</tr>
        <tr id="mo_oauth_name_attr_div">
				<td><strong>'.esc_html__('First Name:','miniorange-login-with-eve-online-google-facebook').'</strong></td>
				<td><input class="mo_table_textbox" required="" placeholder="'.esc_html__('Enter attribute name for First Name','miniorange-login-with-eve-online-google-facebook').'" disabled  type="text" value=""></td>
			</tr>
		<tr>
			<td><strong>'.esc_html__('Last Name:','miniorange-login-with-eve-online-google-facebook').'</strong></td>
			<td>
				<input type="text" class="mo_table_textbox" placeholder="'.esc_html__('Enter attribute name for Last Name','miniorange-login-with-eve-online-google-facebook').'"  disabled /></td>
		</tr>
		<tr>
			<td><strong>'.esc_html__('Email:','miniorange-login-with-eve-online-google-facebook').'</strong></td>
			<td><input type="text" class="mo_table_textbox" placeholder="'.esc_html__('Enter attribute name for Email','miniorange-login-with-eve-online-google-facebook').'"  value="" disabled /></td>
		</tr>
		<tr>
			<td><strong>'.esc_html__('Group/Role:','miniorange-login-with-eve-online-google-facebook').'</strong></td>
			<td><input type="text" class="mo_table_textbox" placeholder="'.esc_html__('Enter attribute name for Group/Role','miniorange-login-with-eve-online-google-facebook').'" value="" disabled /></td>
		</tr>
		<tr>
			<td><strong>'.esc_html__('Display Name:','miniorange-login-with-eve-online-google-facebook').'</strong></td>
			<td><input type="text" class="mo_table_textbox" placeholder="'.esc_html__('Username','miniorange-login-with-eve-online-google-facebook').'" value="" disabled /></td>
		</tr>
			<tr><td colspan="3"><hr></td></tr>
			<tr><td colspan="2">
			<h3>'.esc_html__('Map Custom Attributes ','miniorange-login-with-eve-online-google-facebook').'<a href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank" rel="noopener noreferrer" style="font-size: x-small">[PREMIUM]</a></h3>
			<span style="font-size:small;">[ <a href="https://developers.miniorange.com/docs/oauth/wordpress/client/custom-attribute-mapping" target="_blank">'.esc_html__('How to map Custom Attributes?','miniorange-login-with-eve-online-google-facebook').'</a> ]</span>
            <p>'.esc_html__('Map extra OAuth Provider attributes which you wish to be included in the user profile below','miniorange-login-with-eve-online-google-facebook').'</p>
			</td><td><input disabled type="button" value="+" class="button button-primary"  /></td>
			<td><input disabled type="button" value="-" class="button button-primary"   /></td></tr>
			<tr class="rows"><td><input disabled type="text" placeholder="'.esc_html__('Enter field meta name','miniorange-login-with-eve-online-google-facebook').'" /></td>
			<td><input disabled type="text" placeholder="'.esc_html__('Enter attribute name from OAuth Provider','miniorange-login-with-eve-online-google-facebook').'" class="mo_table_textbox" /></td>
			</tr>';
			?>
			</table>
			<br>
			<input type="submit" name="submit" value="<?php esc_html_e('Save settings','miniorange-login-with-eve-online-google-facebook') ?>"
					class="button button-primary button-large" />
		</form>
		</div>

		<div class="mo_table_layout" id="role-mapping">
		<h3><?php esc_html_e('Role Mapping ','miniorange-login-with-eve-online-google-facebook')?><a href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank" rel="noopener noreferrer" style="font-size: x-small;">[PREMIUM]</a></small></h3>
		<span style="font-size:small;">[ <a href="https://faq.miniorange.com/knowledgebase/map-roles-usergroup/" target="_blank" rel="noopener"><?php esc_html_e('How to map Roles?','miniorange-login-with-eve-online-google-facebook')?></a> ]</span><br><br>
		<b>NOTE: </b><?php esc_html_e('Role will be assigned only to non-admin users (user that do NOT have Administrator privileges). You will have to manually change the role of Administrator users.','miniorange-login-with-eve-online-google-facebook')?><br>
		<form id="role_mapping_form" name="f" method="post" action="">
		<?php wp_nonce_field( 'mo_oauth_role_mapping_form_nonce', 'mo_oauth_role_mapping_form_field' ); ?>
		<input disabled class="mo_table_textbox" required="" type="hidden"  name="mo_oauth_app_name" value="<?php echo esc_attr($currentappname);?>">
		<input disabled  type="hidden" name="option" value="mo_oauth_client_save_role_mapping" />
		
		<p><input disabled type="checkbox"/><strong><?php esc_html_e(' Keep existing user roles','miniorange-login-with-eve-online-google-facebook')?></strong><br><small><?php esc_html_e('Role mapping won\'t apply to existing wordpress users','miniorange-login-with-eve-online-google-facebook')?></small></p>
		<p><input disabled type="checkbox" > <strong><?php esc_html_e(' Do Not allow login if roles are not mapped here ','miniorange-login-with-eve-online-google-facebook')?></strong></p><small><?php esc_html_e('We won\'t allow users to login if we don\'t find users role/group mapped below.','miniorange-login-with-eve-online-google-facebook')?></small></p>

		<div id="panel1">
			<table class="mo_oauth_client_mapping_table" id="mo_oauth_client_role_mapping_table" style="width:90%">
					<tr><td>&nbsp;</td></tr>
					<tr>
					<td><font style="font-size:13px;font-weight:bold;"><?php esc_html_e('Default Role ','miniorange-login-with-eve-online-google-facebook')?></font>
					</td>
					<td>
						<select disabled style="width:100%">
						   <option><?php esc_html_e('Subscriber','miniorange-login-with-eve-online-google-facebook');?></option>
						</select>
						
					</td>
				</tr>
				<tr>
					<td colspan=2><i><?php esc_html_e(' Default role will be assigned to all users for which mapping is not specified.','miniorange-login-with-eve-online-google-facebook'); ?></i></td>
				</tr>
				<tr><td>&nbsp;</td></tr>
				<tr>
					<td style="width:50%"><b><?php esc_html_e('Group Attribute Value','miniorange-login-with-eve-online-google-facebook'); ?></b></td>
					<td style="width:50%"><b><?php esc_html_e('WordPress Role','miniorange-login-with-eve-online-google-facebook'); ?></b></td>
				</tr>
				
				<tr>
					<td><input disabled class="mo_oauth_client_table_textbox" type="text" placeholder="<?php esc_html_e('group name','miniorange-login-with-eve-online-google-facebook'); ?>" />
					</td>
					<td>
						<select disabled style="width:100%"  >
							<option><?php esc_html_e('Subscriber','miniorange-login-with-eve-online-google-facebook'); ?></option>
						</select>
					</td>
				</tr>
				</table>
				<table class="mo_oauth_client_mapping_table" style="width:90%;">
					<tr><td><a style="cursor:pointer"><?php esc_html_e('Add More Mapping','miniorange-login-with-eve-online-google-facebook') ?></a><br><br></td><td>&nbsp;</td></tr>
					<tr>
						<td><input disabled type="submit" class="button button-primary button-large" value="<?php esc_html_e('Save Mapping','miniorange-login-with-eve-online-google-facebook'); ?>" /></td>
						<td>&nbsp;</td>
					</tr>
				</table>
				</div>
			</form>
		</div>
<?php
}

function mooauth_client_dropdownattrmapping( $nestedprefix, $resource_owner_details, $temp ) {
	foreach ( $resource_owner_details as $key => $resource ) {
		if ( is_array( $resource ) ) {
			if ( ! empty( $nestedprefix ) ) {
				$nestedprefix .= '.';
			}
			$temp = mooauth_client_dropdownattrmapping( $nestedprefix . $key, $resource, $temp );
			$nestedprefix = rtrim($nestedprefix,".");
		} else {
			if ( ! empty( $nestedprefix ) ) {
				array_push($temp, $nestedprefix.".".$key);
			}
			else{
				array_push($temp, $key);
			}
		}
	}
	return $temp;
}
