<?php

function mooauth_client_grant_type_settings() {
	?>
	</div>
	<div class="mo_table_layout" id="mo_grant_settings" style="position: relative;">
		<table class="mo_settings_table">
			<tr>
				<td style="padding: 15px 0px 5px;"><h3 style="display: inline;"><?php esc_html_e('Grant Settings','miniorange-login-with-eve-online-google-facebook')?>&emsp;<code><small><a href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank" rel="noopener noreferrer">[PREMIUM]</a></small></code></h3><span style="float: right;">[ <a href="https://developers.miniorange.com/docs/oauth/wordpress/client/multiple-grant-support" target="_blank" rel="noopener">Click here</a> to know how this is useful. ]</span></td>
				<!-- <td align="right"><a href="#" target="_blank" id='mo_oauth_grant_guide' style="display:inline;background-color:#0085ba;color:#fff;padding:4px 8px;border-radius:4px;">What is this?</a></td> -->
			</tr>
		</table>
		<div class="grant_types">
			<h4><?php esc_html_e('Select Grant Type:','miniorange-login-with-eve-online-google-facebook')?></h4>
			<input checked disabled type="checkbox">&emsp;<strong><?php esc_html_e('Authorization Code Grant','miniorange-login-with-eve-online-google-facebook')?></strong>&emsp;<code><small>[DEFAULT]</small></code>
			<blockquote>
				<?php esc_html_e('The Authorization Code grant type is used by web and mobile apps.','miniorange-login-with-eve-online-google-facebook')?><br/>
				<?php esc_html_e('It requires the client to exchange authorization code with access token from the server.','miniorange-login-with-eve-online-google-facebook')?>
				<br/><small>(<?php esc_html_e('If you have doubt on which settings to use, you can leave this checked and disable all others.','miniorange-login-with-eve-online-google-facebook')?>)</small>
			</blockquote>
			<input disabled type="checkbox">&emsp;<strong><?php esc_html_e('Implicit Grant','miniorange-login-with-eve-online-google-facebook')?></strong>
			<blockquote>
				<?php esc_html_e('The Implicit grant type is a simplified version of the Authorization Code Grant flow.','miniorange-login-with-eve-online-google-facebook')?><br/><?php esc_html_e('OAuth providers directly offer access token when using this grant type.','miniorange-login-with-eve-online-google-facebook')?>
			</blockquote>
			<input disabled type="checkbox">&emsp;<strong><?php esc_html_e('Password Grant','miniorange-login-with-eve-online-google-facebook')?></strong>
			<blockquote>
				<?php esc_html_e('Password grant is used by application to exchange user\'s credentials for access token.','miniorange-login-with-eve-online-google-facebook')?><br/>
				<?php esc_html_e('This, generally, should be used by internal applications.','miniorange-login-with-eve-online-google-facebook')?>
			</blockquote>
			<input disabled type="checkbox">&emsp;<strong><?php esc_html_e('Refresh Token Grant','miniorange-login-with-eve-online-google-facebook')?></strong>
			<blockquote>
				<?php esc_html_e('The Refresh Token grant type is used by clients.','miniorange-login-with-eve-online-google-facebook')?><br/>
				<?php esc_html_e('This can help in keeping user session persistent.','miniorange-login-with-eve-online-google-facebook')?>
			</blockquote>
		</div>
		<hr>
		<div style="padding:15px 0px 15px;"><h3 style="display: inline;"><?php esc_html_e('JWT Validation & PKCE','miniorange-login-with-eve-online-google-facebook')?>&emsp;</h3><span style="float: right;">[
		<a href="https://developers.miniorange.com/docs/oauth/wordpress/client/json-web-token-support" target="_blank" rel="noopener">Click here</a> <?php esc_html_e('to know how this is useful.','miniorange-login-with-eve-online-google-facebook')?>  ]</span></div>
				<div>
					<table class="mo_settings_table">
						<tr>
							<td><strong><?php esc_html_e('Enable JWT Verification:','miniorange-login-with-eve-online-google-facebook')?></strong></td>
							<td><input type="checkbox" value="" disabled/></td>
						</tr>
						<tr>
							<td><strong><?php esc_html_e('JWT Signing Algorithm:','miniorange-login-with-eve-online-google-facebook')?></strong></td>
							<td><select disabled>
									<option>HSA</option>
									<option>RSA</option>
								</select>
							</td>
						</tr>
						<tr>
							<td>&nbsp;</td>
							<td>&nbsp;</td>
						</tr>
						<tr>
							<td><strong><?php esc_html_e('PKCE (Proof Key for Code Exchange):','miniorange-login-with-eve-online-google-facebook')?></strong></td>
							<td><input id="pkce_flow" type="checkbox" name="pkce_flow" value="0" disabled/></td>
						</tr>
					</table>
					<p style="font-size:12px"><strong>*Note: </strong><?php esc_html_e('PKCE can be used with Authorization Code Grant and users aren\'t required to provide a client_secret.','miniorange-login-with-eve-online-google-facebook')?></p>
				</div>
			<br><br>
		<div class="notes">
			<hr />
			<?php esc_html_e('Grant Type Settings and JWT Validation & PKCE are configurable in ','miniorange-login-with-eve-online-google-facebook')?><a href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank" rel="noopener noreferrer">premium and enterprise</a><?php esc_html_e(' versions of the plugin.','miniorange-login-with-eve-online-google-facebook')?>
		</div>
	</div>
	<div>
	<?php
}