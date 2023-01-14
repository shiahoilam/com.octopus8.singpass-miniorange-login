<?php

 function mooauth_client_sign_in_settings_ui(){
	?>
<div id="wid-shortcode" class="mo_table_layout">
    <div style="padding:15px 0px 5px;">
        <h2 style="display: inline;">
            <?php esc_html_e('Sign in options','miniorange-login-with-eve-online-google-facebook'); ?></h2><span
            style="float: right;">[ <a
                href="https://developers.miniorange.com/docs/oauth/wordpress/client/login-options" target="_blank"
                rel="noopener"><?php esc_html_e('Click here','miniorange-login-with-eve-online-google-facebook'); ?></a><?php esc_html_e(' to know how this is useful','miniorange-login-with-eve-online-google-facebook')?>.
            ]</span>
    </div>
    <h4><?php esc_html_e('Option 1: Use a Widget','miniorange-login-with-eve-online-google-facebook'); ?></h4>
    <ol>
        <li><?php esc_html_e('Go to Appearances > Widgets.','miniorange-login-with-eve-online-google-facebook'); ?></li>
        <li>Select <b>"<?php echo esc_attr(MO_OAUTH_ADMIN_MENU); ?>"</b>.
            <?php esc_html_e('Drag and drop to your favourite location and save.','miniorange-login-with-eve-online-google-facebook'); ?>
        </li>
    </ol>

    <h4><?php esc_html_e('Option 2: Use a Shortcode','miniorange-login-with-eve-online-google-facebook'); ?> <small
            class=""><a href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank"
                rel="noopener noreferrer">[STANDARD]</a></small></h4>
    <ul>
        <li><?php esc_html_e('Place shortcode','miniorange-login-with-eve-online-google-facebook'); ?>
            <b>[mo_oauth_login]</b>
            <?php esc_html_e('in wordpress pages or posts.','miniorange-login-with-eve-online-google-facebook'); ?>
        </li>
    </ul>
</div>

<!--div class="mo_oauth_premium_option_text"><span style="color:red;">*</span>This is a premium feature.
		<a href="admin.php?page=mo_oauth_settings&tab=licensing">Click Here</a> to see our full list of Premium Features.</div-->
<div id="advanced_settings_sso" class="mo_table_layout ">
    <form id="role_mapping_form" name="f" method="post" action="">
        <?php wp_nonce_field( 'mo_oauth_role_mapping_form_nonce', 'mo_oauth_role_mapping_form_field' ); ?>
        <br>
        <table class="mo_oauth_client_mapping_table" style="width:90%; border-collapse: collapse;">
            <tbody>
                <tr>
                    <td>
                        <h3 style="font-size:18px;">
                            <?php esc_html_e('WordPress User Profile Sync-up Settings','miniorange-login-with-eve-online-google-facebook'); ?>
                        </h3>
                    </td>
                </tr>
                <tr>
                    <td>
                        <font style="font-size:13px;">
                            <?php esc_html_e('Auto register Users','miniorange-login-with-eve-online-google-facebook'); ?>
                        </font> <a
                            href="https://developers.miniorange.com/docs/oauth/wordpress/client/auto-create-users"
                            target="_blank" rel="noopener"><i class="fa fa-info-circle"></i></a> <small class=""><a
                                href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank"
                                rel="noopener noreferrer">[STANDARD]</a></small></strong><br><?php esc_html_e('(If unchecked, only existing users will be able to log-in)','miniorange-login-with-eve-online-google-facebook'); ?>
                        </p>
                    </td>
                    <td><input disabled="true" type="checkbox" checked></td>
                </tr>
                <tr>
                    <td>
                        <font style="font-size:13px;">
                            <?php esc_html_e('Keep Existing Users','miniorange-login-with-eve-online-google-facebook'); ?>
                        </font> <a href="https://developers.miniorange.com/docs/oauth/wordpress/client/account-linking"
                            target="_blank" rel="noopener"><i class="fa fa-info-circle"></i></a> <small class=""><a
                                href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank"
                                rel="noopener noreferrer">[PREMIUM]</a></small><br><?php esc_html_e('(If checked, existing users\' attributes will NOT be overwritten when they log-in','miniorange-login-with-eve-online-google-facebook'); ?>
                        </p>
                    </td>
                    <td><input disabled="true" type="checkbox"></td>
                </tr>
                <tr>
                    <td>
                        <font style="font-size:13px;">
                            <?php esc_html_e('Keep Existing Email Attribute','miniorange-login-with-eve-online-google-facebook'); ?>
                        </font> <a href="https://developers.miniorange.com/docs/oauth/wordpress/client/account-linking"
                            target="_blank" rel="noopener"><i class="fa fa-info-circle"></i></a> <small class=""><a
                                href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank"
                                rel="noopener noreferrer">[PREMIUM]</a></small><br><?php esc_html_e('(If checked, existing users\' only email attribute will NOT be overwritten when they log-in','miniorange-login-with-eve-online-google-facebook'); ?>
                        </p>
                    </td>
                    <td><input disabled="true" type="checkbox"></td>
                </tr>
                <tr class="bordered">
                    <td>&nbsp;</td>
                </tr>
                <tr>
                    <td>
                        <h3 style="font-size:18px;">
                            <?php esc_html_e('Login Settings','miniorange-login-with-eve-online-google-facebook'); ?>
                        </h3>
                    </td>
                </tr>
                <tr>
                    <td>
                        <font style="font-size:13px;">
                            <?php esc_html_e('Custom redirect URL after login','miniorange-login-with-eve-online-google-facebook'); ?>
                        </font><a
                            href="https://developers.miniorange.com/docs/oauth/wordpress/client/custom-redirection#post-login-redirection"
                            target="_blank" rel="noopener"><i class="fa fa-info-circle"></i></a><small class=""> <a
                                href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank"
                                rel="noopener noreferrer">[STANDARD]</a></small><br><?php esc_html_e('(Keep blank in case you want users to redirect to page from where SSO originated)','miniorange-login-with-eve-online-google-facebook'); ?>
                        </p>
                    </td>
                    <td><input disabled="true" type="text" style="width:100%;"></td>
                </tr>
                <tr>
                    <td>
                        <font style="font-size:13px;">
                            <?php esc_html_e('Hide & Disable WP Login / Block WordPress Login','miniorange-login-with-eve-online-google-facebook'); ?>
                        </font> <small class=""><a href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank"
                                rel="noopener noreferrer">[ENTERPRISE]</a></small></p>
                    </td>
                    <td><input disabled="true" type="checkbox"></td>
                </tr>
                <tr class="bordered">
                    <td>&nbsp;</td>

                </tr>
                <tr>
                    <td>
                        <h3 style="font-size:18px;">
                            <?php esc_html_e('Logout Settings','miniorange-login-with-eve-online-google-facebook'); ?>
                        </h3>
                    </td>
                </tr>
                <tr>
                    <td>
                        <font style="font-size:13px;">
                            <?php esc_html_e('Custom redirect URL after logout','miniorange-login-with-eve-online-google-facebook'); ?>
                        </font><a
                            href="https://developers.miniorange.com/docs/oauth/wordpress/client/custom-redirection#post-logout-redirection"
                            target="_blank" rel="noopener"><i class="fa fa-info-circle"></i></a><small class=""> <a
                                href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank"
                                rel="noopener noreferrer">[STANDARD]</a></small>
                    </td>
                    <td><input disabled="true" type="text" style="width:100%;"></td>
                </tr>
                <tr>
                    <td>
                        <font style="font-size:13px;">
                            <?php esc_html_e('Confirm when logging out','miniorange-login-with-eve-online-google-facebook'); ?>
                        </font><small class=""><a href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank"
                                rel="noopener noreferrer">[ENTERPRISE]</a></small><br><?php esc_html_e('(If checked, users will be ASKED to confirm if they want to log-out, when they click the widget/shortcode logout button','miniorange-login-with-eve-online-google-facebook'); ?>
                        </p>
                    </td>
                    <td><input disabled="true" type="checkbox"></td>
                </tr>
                <tr class="bordered">
                    <td>&nbsp;</td>
                </tr>
                <tr>
                    <td>
                        <h3 style="font-size:18px;">
                            <?php esc_html_e('WordPress Site Access Control (Security Settings)','miniorange-login-with-eve-online-google-facebook'); ?>
                        </h3>
                    </td>
                </tr>
                <tr>
                    <td>
                        <font style="font-size:13px;">
                            <?php esc_html_e('Restrict site to logged in users','miniorange-login-with-eve-online-google-facebook'); ?>
                            <a href="https://developers.miniorange.com/docs/oauth/wordpress/client/forced-authentication"
                                target="_blank" rel="noopener"><i class="fa fa-info-circle"></i></a><small class=""> <a
                                    href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank"
                                    rel="noopener noreferrer">[ENTERPRISE]</a></small>
                        </font>
                        <br><?php esc_html_e('(Users will be auto redirected to OAuth login if not logged in)','miniorange-login-with-eve-online-google-facebook'); ?>
                        </p>
                    </td>
                    <td><input disabled="true" type="checkbox"></td>
                </tr>
                <tr>
                    <td>
                        <font style="font-size:13px;">
                            <?php esc_html_e('Allowed Domains / Whitelisted Domains','miniorange-login-with-eve-online-google-facebook'); ?>
                        </font> <small class=""><a href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank"
                                rel="noopener noreferrer">[ENTERPRISE]</a></small><br>(Comma separated domains ex.
                        domain1.com,domain2.com etc)</p>
                    </td>
                    <td><input disabled="true" type="text" placeholder="domain1.com,domain2.com" style="width:100%;">
                    </td>
                </tr>
                <tr>
                    <td>
                        <font style="font-size:13px;">
                            <?php esc_html_e('Restricted Domains / Blacklisted Domains','miniorange-login-with-eve-online-google-facebook'); ?>
                        </font> <small class=""><a href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank"
                                rel="noopener noreferrer">[ENTERPRISE]</a></small><br>(Comma separated domains ex.
                        domain1.com,domain2.com etc)</p>
                    </td>
                    <td><input disabled="true" type="text" placeholder="domain1.com,domain2.com" style="width:100%;">
                    </td>
                </tr>
                <tr class="bordered">
                    <td>&nbsp;</td>
                </tr>
                <tr>
                    <td>
                        <h3 style="font-size:18px;">
                            <?php esc_html_e('SSO Window Settings','miniorange-login-with-eve-online-google-facebook'); ?>
                        </h3>
                    </td>
                </tr>
                <tr>
                    <td>
                        <font style="font-size:13px;">
                            <?php esc_html_e('Open login window in Popup','miniorange-login-with-eve-online-google-facebook'); ?>
                        </font><a
                            href="https://developers.miniorange.com/docs/oauth/wordpress/client/custom-redirection#post-login-redirection"
                            target="_blank" rel="noopener"><i class="fa fa-info-circle"></i></a> <small class=""><a
                                href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank"
                                rel="noopener noreferrer">[ENTERPRISE]</a></small><br><?php esc_html_e('(Keep blank in case you want users to redirect to page from where SSO originated)','miniorange-login-with-eve-online-google-facebook'); ?>
                        </p>
                    </td>
                    <td><input disabled="true" type="checkbox"></td>
                </tr>
                <tr>
                    <td>
                        <font style="font-size:13px;">
                            <?php esc_html_e('Enable Single Login Flow','miniorange-login-with-eve-online-google-facebook'); ?>
                        </font>
                        </font><a
                            href="https://developers.miniorange.com/docs/oauth/wordpress/client/custom-redirection#post-logout-redirection"
                            target="_blank" rel="noopener"><i class="fa fa-info-circle"></i></a> <small class=""><a
                                href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank"
                                rel="noopener noreferrer">[ENTERPRISE]</a></small>
                    </td>
                    <td><input disabled="true" type="checkbox"></td>
                </tr>
                <tr class="bordered">
                    <td>&nbsp;</td>
                </tr>
                <tr>
                    <td>
                        <h3 style="font-size:18px;">
                            <?php esc_html_e('User Login Audit / Login Reports','miniorange-login-with-eve-online-google-facebook'); ?>
                        </h3>
                    </td>
                </tr>
                <tr class="bordered">
                    <td>
                        <font style="font-size:13px;">
                            <?php esc_html_e('Enable User login reports','miniorange-login-with-eve-online-google-facebook'); ?>
                        </font><a href="https://developers.miniorange.com/docs/oauth/wordpress/client/user-analytics"
                            target="_blank" rel="noopener"><i class="fa fa-info-circle"></i></a> <small class=""><a
                                href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank"
                                rel="noopener noreferrer">[ENTERPRISE]</a></small></p>
                    </td>
                    <td><input disabled="true" type="checkbox"></td>
                </tr>
                <tr>
                    <td>
                        <h3 style="font-size:18px;">
                            <?php esc_html_e('Other Settings','miniorange-login-with-eve-online-google-facebook'); ?>
                        </h3>
                    </td>
                </tr>
                <tr>
                    <td>
                        <font style="font-size:13px;">
                            <?php esc_html_e('Dynamic Callback URL','miniorange-login-with-eve-online-google-facebook'); ?>
                        </font><a
                            href="https://developers.miniorange.com/docs/oauth/wordpress/client/dynamic-callback-url"
                            target="_blank" rel="noopener"><i class="fa fa-info-circle"></i></a> </small><small
                            class=""><a href="admin.php?page=mo_oauth_settings&tab=licensing" target="_blank"
                                rel="noopener noreferrer">[ENTERPRISE]</a></small>
                    </td>
                    <td><input disabled="true" type="text" style="width:100%;"></td>
                </tr>
                <tr>
                    <td>&nbsp;</td>
                </tr>
                <tr>
                    <td><input disabled="true" type="submit" class="button button-primary button-large"
                            value="<?php esc_html_e('Save Settings','miniorange-login-with-eve-online-google-facebook'); ?>">
                    </td>
                    <td>&nbsp;</td>
                </tr>
            </tbody>
        </table>
    </form>
</div>

<?php
}
