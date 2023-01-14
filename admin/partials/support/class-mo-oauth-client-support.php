<?php

class MOOAuth_Client_Admin_Support {

	public static function support() {
		self::support_page();
		self::mo_download_log();
	}

	public static function support_page(){
	?>
<div id="mo_support_layout" class="mo_support_layout">
    <div style="width:97%;margin:0 auto;">
        <h3 class=" attribute-mapping-title" style="margin-top: 0;">
            <?php esc_html_e('Contact Us','miniorange-login-with-eve-online-google-facebook')?>
        </h3>
        <div style="display: flex;align-items: center;gap:6px;">
            <div><img src=" <?php echo esc_url(plugin_dir_url( __FILE__ )) . 'call.png'?>">
            </div>
            <div style="font-size:13px;">
                <?php _e('Need any help? Just give us a call at', 'miniorange-login-with-eve-online-google-facebook')?><b>
                    +1
                    978 658 9387</b>
            </div>
        </div>
        <p><?php esc_html_e('Couldn\'t find an answer in ','miniorange-login-with-eve-online-google-facebook')?><a
                href="https://faq.miniorange.com/kb/oauth-openid-connect" target="_blank">FAQ</a>?<br>
            <?php esc_html_e('Just send us a query and we will get back to you soon.','miniorange-login-with-eve-online-google-facebook')?>
        </p>
        <form method="post" action="">
            <?php wp_nonce_field('mo_oauth_support_form','mo_oauth_support_form_field'); ?>
            <input type="hidden" name="option" value="mo_oauth_contact_us_query_option" />
    <div class="contact">
            <table class="mo_settings_table" style="display: none;">
                <input type="email" class="contact-input-fields" placeholder="Enter your email"
                    name="mo_oauth_contact_us_email" value="<?php echo esc_attr(get_option('mo_oauth_admin_email')); ?>"
                    required />
                <input type="tel" id="contact_us_phone" class="mo_settings_table contact-input-fields" type="tel" id="contact_us_phone"
                    placeholder="Enter your phone number" name="mo_oauth_contact_us_phone"
                    value="<?php echo esc_attr(get_option('mo_oauth_client_admin_phone'));?>"
                    pattern="[\+]\d{11,14}|[\+]\d{1,4}[\s]\d{9,10}|[\+]\d{1,4}[\s]" />
                <textarea cols="30" rows="6"
                    placeholder="<?php esc_attr_e('Enter your query...','miniorange-login-with-eve-online-google-facebook'); ?>"
                    name="mo_oauth_contact_us_query" onkeypress="mo_oauth_valid_query(this)"
                    onkeyup="mo_oauth_valid_query(this)" rows="4" style="resize: vertical;" onblur="mo_oauth_valid_query(this)" required></textarea>

                <div class="checkbox-pair">
                    <input id="mo_oauth_send_plugin_config" class="checkbox" type="checkbox"
                        name="mo_oauth_send_plugin_config" checked />
                    <div class="checkbox-content">
                        <span class="checkbox-info">
                            <?php esc_html_e('Send Plugin Configuration','miniorange-login-with-eve-online-google-facebook')?>
                        </span>
                        <span class="checkbox-disclaimer">
                            <?php esc_html_e('We will not be sending your Client IDs or Client Secrets.','miniorange-login-with-eve-online-google-facebook')?>
                        </span>
                    </div>
                </div>
            </table>
                <div class="setup-call">
                    <label class="mo_oauth_switch">
                        <input id="oauth_setup_call" type="checkbox" style="background: #dcdad1"
                            name="oauth_setup_call" />
                        <span class="mo_oauth_slider round"></span>
                    </label>
                    <p>
                        <b>
                            <label for="oauth_setup_call"></label>
                            <?php esc_html_e('Setup a Call/ Screen-share session','miniorange-login-with-eve-online-google-facebook');?>
                        </b>
                    </p>

                </div>
                <div id="mo_oauth_setup_call_div">
                    <table class="mo_settings_table" cellpadding="2" cellspacing="2">
                        <tr>
                            <td><strong>
                                    <font color="#FF0000">*</font>
                                    <?php esc_html_e('Issue:','miniorange-login-with-eve-online-google-facebook')?></td>
                            </strong></td>
                            <td><select id="issue_dropdown" class="mo_callsetup_table_textbox"
                                    name="mo_oauth_setup_call_issue">
                                    <option disabled selected>--------Select Issue type--------</option>
                                    <option id="sso_setup_issue">SSO Setup Issue</option>
                                    <option>Custom requirement</option>
                                    <option id="other_issue">Other</option>
                                </select></td>
                        </tr>
                        <tr id="setup_guide_link" style="display: none;">
                            <td colspan="2">
                                <?php esc_html_e('Have you checked the setup guide ','miniorange-login-with-eve-online-google-facebook')?><a
                                    href="https://plugins.miniorange.com/wordpress-single-sign-on-sso-with-oauth-openid-connect"
                                    target="_blank">here</a>?</td>
                        </tr>
                        <tr id="required_mark" style="display: none;">
								<td><strong><font color="#FF0000">*</font><?php esc_html_e('Description:','miniorange-login-with-eve-online-google-facebook')?></td></strong></td>
									<td><textarea id="issue_description" class="mo_oauth_issue_description" onkeypress="mo_oauth_valid_query(this)" placeholder="<?php esc_html_e('Enter your issue description here','miniorange-login-with-eve-online-google-facebook'); ?>" onkeyup="mo_oauth_valid_query(this)" onblur="mo_oauth_valid_query(this)" name="mo_oauth_issue_description" rows="2" style="resize: vertical;"></textarea></td>								
						</tr>
                        <tr>
                            <td><strong>
                                    <font color="#FF0000">*</font>
                                    <?php esc_html_e('Date:','miniorange-login-with-eve-online-google-facebook')?></td>
                            </strong></td>
                            <td><input class="mo_callsetup_table_textbox" name="mo_oauth_setup_call_date" type="text"
                                    id="calldate"></td>
                        </tr>
                        <tr>
                            <td><strong>
                                    <font color="#FF0000">*</font>
                                    <?php esc_html_e('Local Time:','miniorange-login-with-eve-online-google-facebook')?>
                            </td></strong></td>
                            <td><input class="mo_callsetup_table_textbox" name="mo_oauth_setup_call_time" type="time"
                                    id="mo_oauth_setup_call_time"></td>
                        </tr>
                    </table>
                    <p><?php esc_html_e('We are available from 3:30 to 18:30 UTC','miniorange-login-with-eve-online-google-facebook')?>
                    </p>
                    <input type="hidden" name="mo_oauth_time_diff" id="mo_oauth_time_diff">
                </div>
                <div>
                    <input type="submit" name="submit" class="submit-btn"value="Submit" />
                </div>
            </div>
        </form>
    </div>
</div>

<br />

<?php
	}

	public static function mo_download_log() {
		?>


<div class="mo_enable_logs_wrapper">
    <div class="mo_oauth_support_layout mo_enable_logs">
        <div class="mo_debug">
        <div class="setup-call">
        <form id="mo_oauth_enable_debug_log_form" method="post">
            <input type="hidden" name="option" value="mo_oauth_reset_debug" />
                <?php wp_nonce_field( 'mo-oauth-Debug-logs-unique-string-nonce', 'mo_oauth_reset_debug' ); ?>
                    <label class="mo_oauth_switch">
                        <input id="mo_oauth_debug_check" style="background: #dcdad1"  type="checkbox" name="mo_oauth_debug_check" <?php if(get_option('mo_debug_enable')){echo get_option('mo_debug_enable')==="on"?'checked':'unchecked';} ?> />
                        <span class="mo_oauth_slider round"></span>
                    </label>

    </form>
                    <p>
                        <b>
                            <label for="oauth_enable_logs"></label>
                            <?php esc_html_e('Enable Debug Log','miniorange-login-with-eve-online-google-facebook');?>
                        </b>
                    </p>

                </div>
                <p class="logs-disclaimer">
                    The error logs will be cleared on a weekly basis
                </p>

                <div id="mo_oauth_enable" >
            <form id="mo_oauth_debug_download_form" method="post">
                <input type="hidden" name="option" value="mo_oauth_enable_debug_download" />
                <?php wp_nonce_field( 'mo_oauth_enable_debug_download', 'mo_oauth_enable_debug_download_nonce' ); ?>
                
                <input type="submit" name="submit" value="Download Logs" class="download-logs-btn" />
            </form>

            <form id="mo_oauth_clear_debug_log_form" method="post">
            <input type="hidden" name="option" value="mo_oauth_clear_debug" />
            <?php wp_nonce_field( 'mo_oauth_clear_debug', 'mo_oauth_clear_debug_nonce' ); ?>
                <div class="checkbox-pair">                   
                </div>
                <input type="submit" name="submit" id="submit_clear" value="Clear Logs" class="download-logs-btn" />
            </form>

            </div>
        </div>
    </div>
</div>
<br>



<div class="cstm-iframe">
    <div class="cstm-addon-row">
        <div class="col-md-2 text-center">
            <img src="<?php echo esc_url(plugin_dir_url( __FILE__ )) . 'card-logo.png'?>">
        </div>
        <div class="col-md-10 text-dark">
            <h5 style="margin-top: 12px"><a class="card-title"
                    href="https://plugins.miniorange.com/wordpress-rest-api-authentication" target="_target"
                    class="cstm-h4 text-dark">WordPress REST API Authentication</a>
            </h5>
            <h4>
                <span class="h3 text-secondary">By</span><span><a rel="nofollow" href="https://miniorange.com/"
                        target="_blank" class="">&nbsp;miniOrange</a></span>
            </h4>
            <div class="text-warning">
                <div class="ratings">
                    <img src="<?php echo esc_url(plugin_dir_url( __FILE__ )) . 'ratings.png'?>">

                </div>
                <span><a href="https://wordpress.org/plugins/wp-rest-api-authentication/#reviews" target="_blank"
                        class="text-secondary">(41)</a></span>
            </div>
        </div>
    </div>
    <p class="mt-2 pl-2 cstm-content">
        Secure and protect your WordPress REST API endpoints from unauthorized access with our REST API Authentication
        using highly secure authentication methods.
    </p>
    <a class="card-download-btn" href="https://wordpress.org/plugins/wp-rest-api-authentication/" target="_blank">Download
        Now</a>
</div>
<?php
	}

}
