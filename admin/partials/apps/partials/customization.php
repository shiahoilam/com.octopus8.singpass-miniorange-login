<?php

 function mooauth_client_customization_ui(){	
	?>
	
	<div id="mo_oauth_customiztion" class="mo_table_layout">
	<form id="form-common" name="form-common" method="post" action="admin.php?page=mo_oauth_settings&tab=customization">
		<?php wp_nonce_field( 'mo_oauth_common_form', 'mo_oauth_common_form_field' ); ?>
		</form>
		<div style="padding:15px 0px 15px;"><h2 style="display: inline;"><?php esc_html_e('Customize Icons','miniorange-login-with-eve-online-google-facebook'); ?> <small><a href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank" rel="noopener noreferrer">[STANDARD]</a></small></h2><span style="float: right;">[
		<a href="https://developers.miniorange.com/docs/oauth/wordpress/client/login-button-customization" target="_blank" rel="noopener"><?php esc_html_e('Click here','miniorange-login-with-eve-online-google-facebook'); ?></a> <?php esc_html_e('to know how this is useful.','miniorange-login-with-eve-online-google-facebook'); ?> ]</span></div>
	
		<table class="mo_settings_table">
			<tr>
				<td><strong><?php esc_html_e('Icon Width','miniorange-login-with-eve-online-google-facebook'); ?>:</strong></td>
				<td><input disabled type="text"> e.g. 200px or 100%</td>
			</tr>
			<tr>
				<td><strong><?php esc_html_e('Icon Height','miniorange-login-with-eve-online-google-facebook'); ?>:</strong></td>
				<td><input disabled type="text"> e.g. 50px or auto</td>
			</tr>
			<tr>
				<td><strong><?php esc_html_e('Icon Margins','miniorange-login-with-eve-online-google-facebook'); ?>:</strong></td>
				<td><input disabled type="text"> e.g. 2px 0px or auto</td>
			</tr>
			<tr>
				<td><strong><?php esc_html_e('Custom CSS','miniorange-login-with-eve-online-google-facebook'); ?>:</strong></td>
				<td><textarea disabled type="text" style="resize: vertical; width:400px; height:180px;  margin:5% auto;" rows="6"></textarea><br/><b>Example CSS:</b> 
<pre>.oauthloginbutton{
	background: #7272dc;
	height:40px;
	padding:8px;
	text-align:center;
	color:#fff;
}</pre>
			</td>
			</tr>
			<tr>
				<td><strong><?php esc_html_e('Custom Logout button text','miniorange-login-with-eve-online-google-facebook'); ?>:</strong></td>
				<td><input disabled type="text" style="resize: vertical; width:200px; height:30px;  margin:5% auto;" placeholder ="Howdy ,##user##"> <b>##user##</b> is replaced by Username</td>
			</tr>
			<tr>
				<td>&nbsp;</td>
				<td><input disabled value=" 	<?php esc_html_e('Save settings','miniorange-login-with-eve-online-google-facebook'); ?> " class="button button-primary button-large" /></td>
			</tr>
		</table>
	</form>
	</div>
		
	<?php
}
