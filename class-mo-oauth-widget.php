<?php

include 'mo_oauth_log.php';

class MOOAuth_Widget extends WP_Widget
{

    public function __construct()
    {
        update_option('host_name', 'https://login.xecurify.com');
        add_action('wp_enqueue_scripts', array($this, 'mo_oauth_register_plugin_styles'));
        add_action('init', array($this, 'mo_oauth_start_session'));
        add_action('wp_logout', array($this, 'mo_oauth_end_session'));
        add_action('login_form', array($this, 'mo_oauth_wplogin_form_button'));
        parent::__construct('mooauth_widget', MO_OAUTH_ADMIN_MENU, array('description' => __('Login to Apps with OAuth', 'flw'), ));

    }

    function mo_oauth_wplogin_form_style()
    {

        wp_enqueue_style('mo_oauth_fontawesome', plugins_url('css/font-awesome.css', __FILE__));
        wp_enqueue_style('mo_oauth_wploginform', plugins_url('css/login-page.css', __FILE__), array(), MO_OAUTH_CSS_JS_VERSION);
    }

    function mo_oauth_wplogin_form_button()
    {
        $appslist = get_option('mo_oauth_apps_list');

        $show_qr_code = get_option(MosingpassPlugin::SHOW_QR);
        if ($show_qr_code) {
            MosingpassPlugin::show_qr_code();
        } else {
            if (is_array($appslist) && sizeof($appslist) > 0) {
                $this->mo_oauth_load_login_script();
                foreach ($appslist as $key => $app) {
                    if (isset($app['show_on_login_page']) && $app['show_on_login_page'] === 1) {

                        $this->mo_oauth_wplogin_form_style();
                        $logo_class = $this->mo_oauth_client_login_button_logo($app['appId']);
                        $btn_text = '<div class=" mo_oauth_login_button_text "><i class="' . esc_attr($logo_class) . ' mo_oauth_login_button_icon"></i>Login with ' . esc_attr(ucwords($key)) . '</div>';
                        if ($key === get_option(MosingpassPlugin::APP_NAME)) {
                            $btn_text = '<div class="singpass-header-btn">Log in with <img src="' . plugin_dir_url(__FILE__) . '/images/singpass-login-icon.svg" alt="SingPass"></div>';
                        }
                        echo '
					<script>
					window.onload = function() {
						var target_btn = document.getElementById("mo_oauth_widget_parent");
						var before_element = document.querySelector(" #wp-submit ");
						before_element.after(target_btn);
					};                  
					</script>
					<div id="mo_oauth_widget_parent" >
						<div class="mo_oauth_or_division" style="text-align:center">
							<br><br><b>OR</b>
						</div>
						<div id="mo_oauth_login_button_field" style="height:40px;margin-top:20px;">
							<div id="mo_oauth_login_button">
							<a class=" mo_oauth_button_div" style="text-decoration:none" href="javascript:void(0)" onClick="moOAuthLoginNew(\'' . esc_attr($key) . '\')">
							' . $btn_text .
                            '</a></div>
						</div>
					</div>';
                        /*
                                                echo '
                                            <script>
                                            window.onload = function() {
                                                var target_btn = document.getElementById("mo_oauth_widget_parent");
                                                var before_element = document.querySelector(" #wp-submit ");
                                                before_element.after(target_btn);
                                            };
                                            </script>
                                            <div id="mo_oauth_widget_parent" >
                                                <div class="mo_oauth_or_division" style="text-align:center">
                                                    <br><br><b>OR</b>
                                                </div>
                                                <div id="mo_oauth_login_button_fie		<divyle="height:40px;margin-top:20px;">
                                                    <div id="mo_oauth_login_button">
                                                        <a class="mo_oauth_button_div button-primary " style="text-decoration:none" href="javascript:void(0)" onClick="moOAuthLoginNew(\'' . esc_attr($key) . '\')"><div class=" mo_oauth_login_button_text "><i class="' . esc_attr($logo_class) . ' mo_oauth_login_button_icon"></i>Login with ' . esc_attr(ucwords($key)) . '</div></a>
                                                    </div>
                                                </div>
                                            </div>';
                        */
                    }
                }
            }
        }

    }

    function mo_oauth_client_login_button_logo($currentAppId)
    {
        $currentapp = mooauth_client_get_app($currentAppId);
        $logo_class = $currentapp->logo_class;
        return $logo_class;
    }

    function mo_oauth_start_session()
    {
        if (!session_id() && !mooauth_client_is_ajax_request() && !mooauth_client_is_rest_api_call()) {
            session_start();
        }

        if (isset($_REQUEST['option']) and $_REQUEST['option'] == 'testattrmappingconfig') {
            $mo_oauth_app_name = sanitize_text_field($_REQUEST['app']);
            wp_redirect(site_url() . '?option=oauthredirect&app_name=' . urlencode($mo_oauth_app_name) . "&test=true");
            exit();
        }

    }

    function mo_oauth_end_session()
    {
        if (!session_id()) {
            session_start();
        }
        session_destroy();
    }

    public function widget($args, $instance)
    {
        extract($args);
        echo $args['before_widget'];
        if (!empty($wid_title)) {
            echo $args['before_title'] . $wid_title . $args['after_title'];
        }

        $this->mo_oauth_login_form();
        echo $args['after_widget'];
    }

    public function mo_oauth_update($new_instance, $old_instance)
    {
        $instance = array();
        if (isset($new_instance['wid_title']))
            $instance['wid_title'] = strip_tags($new_instance['wid_title']);

        return $instance;
    }

    public function mo_oauth_login_form()
    {
        global $post;
        $this->mo_oauth_error_message();
        //$temp = '';

        $appslist = get_option('mo_oauth_apps_list');
        if ($appslist && sizeof($appslist) > 0)
            $appsConfigured = true;

        if (!is_user_logged_in()) {

            if (isset($appsConfigured) && $appsConfigured) {

                $this->mo_oauth_wplogin_form_style();
                $this->mo_oauth_load_login_script();

                $style = get_option('mo_oauth_icon_width') ? "width:" . get_option('mo_oauth_icon_width') . ";" : "";
                $style .= get_option('mo_oauth_icon_height') ? "height:" . get_option('mo_oauth_icon_height') . ";" : "";
                $style .= get_option('mo_oauth_icon_margin') ? "margin:" . get_option('mo_oauth_icon_margin') . ";" : "";
                $custom_css = get_option('mo_oauth_icon_configure_css');
                if (empty($custom_css))
                    echo '<style>.oauthloginbutton{background: #7272dc;height:40px;padding:8px;text-align:center;color:#fff;}</style>';
                else
                    echo '<style>' . esc_html($custom_css) . '</style>';

                if (is_array($appslist)) {
                    foreach ($appslist as $key => $app) {
                        $logo_class = $this->mo_oauth_client_login_button_logo($app['appId']);
                        echo '<a style="text-decoration:none" 
                        href="javascript:void(0)" 
                        onClick="moOAuthLoginNew(\'' . esc_attr($key) . '\');"><div class="mo_oauth_login_button_widget"><i class="' . esc_attr($logo_class) . ' mo_oauth_login_button_icon_widget"></i><h3 class="mo_oauth_login_button_text_widget">Login with ' . esc_attr(ucwords($key)) . '</h3></div></a>';

                    }
                }

            } else {
                echo '<div>No apps configured.</div>';
            }
        } else {
            $current_user = wp_get_current_user();
            $link_with_username = __('Howdy, ', 'flw') . $current_user->display_name;
            echo "<div id=\"logged_in_user\" class=\"login_wid\">
			<li>" . esc_attr($link_with_username) . " | <a href=\"" . esc_url(wp_logout_url(site_url())) . "\" >Logout</a></li>
		</div>";

        }
    }

    private function mo_oauth_load_login_script()
    {
        ?>
        <script type="text/javascript">

            function HandlePopupResult(result) {
                window.location.href = result;
            }

            function moOAuthLoginNew(app_name) {
                window.location.href = '<?php echo esc_attr(site_url()) ?>' + '/?option=oauthredirect&app_name=' + app_name;
            }
        </script>
        <?php
    }


    public function mo_oauth_error_message()
    {
        if (isset($_SESSION['msg']) and $_SESSION['msg']) {
            echo '<div class="' . esc_attr($_SESSION['msg_class']) . '">' . esc_attr($_SESSION['msg']) . '</div>';
            unset($_SESSION['msg']);
            unset($_SESSION['msg_class']);
        }
    }

    public function mo_oauth_register_plugin_styles()
    {
        wp_enqueue_style('style_login_widget', plugins_url('css/style_login_widget.css', __FILE__));
    }


}

function mooauth_update_email_to_username_attr($currentappname)
{
    $appslist = get_option('mo_oauth_apps_list');
    $appslist[$currentappname]['username_attr'] = $appslist[$currentappname]['email_attr'];
    update_option('mo_oauth_apps_list', $appslist);
}

function mooauth_login_validate()
{
    $singpassappname = "singpassappname";
    if (class_exists('MosingpassPlugin')) {
        $singpassappname = get_option(MosingpassPlugin::APP_NAME);
    }
    /* Handle Authorize request */
    if (isset($_REQUEST['option']) and strpos($_REQUEST['option'], 'oauthredirect') !== false) {
        $appname = sanitize_text_field($_REQUEST['app_name']);
        $appslist = get_option('mo_oauth_apps_list');
        if (isset($_REQUEST['redirect_url'])) {
            update_option('mo_oauth_redirect_url', sanitize_text_field($_REQUEST['redirect_url']));
        }

        if (isset($_REQUEST['test']))
            setcookie("mo_oauth_test", true, 0, '/', '', true, true);
        else
            setcookie("mo_oauth_test", false, 0, '/', '', true, true);

        if ($appslist == false) {
            MOOAuth_Debug::mo_oauth_log('ERROR : Looks like you have not configured OAuth provider, please try to configure OAuth provider first');
            exit("Looks like you have not configured OAuth provider, please try to configure OAuth provider first");
        }

        foreach ($appslist as $key => $app) {
            try {
                if (class_exists('MosingpassPlugin')) {
                    MosingpassPlugin::writeLog($appname, 'appname');
                    // MosingpassPlugin::writeLog($app, 'app');
                }
            } catch (Exception $e) {

            }

            if ($appname == $key && (isset($app['send_state']) !== true || $app['send_state'] | $app['appId'] == 'oauth1' || $app['appId'] == 'twitter')) {
                if ($app['appId'] == "twitter" || $app['appId'] == 'oauth1') {
                    include "custom-oauth1.php";
                    setcookie('tappname', $appname, null, null, null, true, true);
                    MOOAuth_Custom_OAuth1::mo_oauth1_auth_request(sanitize_text_field($_COOKIE['tappname']));
                    exit();
                }
                try {
                    if (class_exists('MosingpassPlugin')) {
                        if ($appname === $singpassappname) {
                            MosingpassPlugin::loadSingPassTest($appname, $app);
                            exit();
                        }
                    }
                } catch (Exception $e) {

                }

                $state = base64_encode($appname);
                $authorizationUrl = $app['authorizeurl'];

                if (strpos($authorizationUrl, '?') !== false)
                    $authorizationUrl = $authorizationUrl . "&client_id=" . $app['clientid'] . "&scope=" . $app['scope'] . "&redirect_uri=" . $app['redirecturi'] . "&response_type=code&state=" . $state;
                else
                    $authorizationUrl = $authorizationUrl . "?client_id=" . $app['clientid'] . "&scope=" . $app['scope'] . "&redirect_uri=" . $app['redirecturi'] . "&response_type=code&state=" . $state;

                if (strpos($authorizationUrl, 'apple') !== false) {
                    $authorizationUrl = str_replace("response_type=code", "response_type=code+id_token", $authorizationUrl);
                    $authorizationUrl = $authorizationUrl . "&response_mode=form_post";
                }

                if (session_id() == '' || !isset($_SESSION))
                    session_start();
                $_SESSION['oauth2state'] = $state;
                $_SESSION['appname'] = $appname;

                MOOAuth_Debug::mo_oauth_log('Authorization Request Sent => ' . $authorizationUrl);
                header('Location: ' . $authorizationUrl);
                exit;
            } else {
                $state = null;
                $authorizationUrl = $app['authorizeurl'];

                if (strpos($authorizationUrl, '?') !== false)
                    $authorizationUrl = $authorizationUrl . "&client_id=" . $app['clientid'] . "&scope=" . $app['scope'] . "&redirect_uri=" . $app['redirecturi'] . "&response_type=code";
                else
                    $authorizationUrl = $authorizationUrl . "?client_id=" . $app['clientid'] . "&scope=" . $app['scope'] . "&redirect_uri=" . $app['redirecturi'] . "&response_type=code";

                if (session_id() == '' || !isset($_SESSION))
                    session_start();
                $_SESSION['oauth2state'] = $state;
                $_SESSION['appname'] = $appname;

                MOOAuth_Debug::mo_oauth_log('Authorization Request Sent => ' . $authorizationUrl);
                header('Location: ' . $authorizationUrl);
                exit;
            }
        }
    } else if (strpos($_SERVER['REQUEST_URI'], "openidcallback") !== false || ((strpos($_SERVER['REQUEST_URI'], "oauth_token") !== false) && (strpos($_SERVER['REQUEST_URI'], "oauth_verifier")))) {

        $appslist = get_option('mo_oauth_apps_list');
        $username_attr = "";
        $currentapp = false;
        foreach ($appslist as $key => $app) {
            if ($key == $_COOKIE['tappname']) {
                include "custom-oauth1.php";
                $currentapp = $app;
                if (isset($app['username_attr'])) {
                    $username_attr = $app['username_attr'];
                } else if (isset($app['email_attr'])) {
                    mooauth_update_email_to_username_attr(sanitize_text_field($_COOKIE['tappname']));
                    $username_attr = $app['email_attr'];
                }
            }
        }

        $resourceOwner = MOOAuth_Custom_OAuth1::mo_oidc1_get_access_token(sanitize_text_field($_COOKIE['tappname']));

        $username = "";
        update_option('mo_oauth_attr_name_list', $resourceOwner);
        //TEST Configuration
        if (isset($_COOKIE['mo_oauth_test']) && $_COOKIE['mo_oauth_test']) {
            setcookie("mo_oauth_test", false, null, null, null, true, true);
            echo '<div style="font-family:Calibri;padding:0 3%;">';
            echo '<style>table{border-collapse:collapse;}th {background-color: #eee; text-align: center; padding: 8px; border-width:1px; border-style:solid; border-color:#212121;}tr:nth-child(odd) {background-color: #f2f2f2;} td{padding:8px;border-width:1px; border-style:solid; border-color:#212121;}</style>';
            echo "<h2>Test Configuration</h2><table><tr><th>Attribute Name</th><th>Attribute Value</th></tr>";
            mooauth_client_testattrmappingconfig("", $resourceOwner);
            echo "</table>";
            echo '<div style="padding: 10px;"></div><input style="padding:1%;width:100px;background: #0091CD none repeat scroll 0% 0%;cursor: pointer;font-size:15px;border-width: 1px;border-style: solid;border-radius: 3px;white-space: nowrap;box-sizing: border-box;border-color: #0073AA;box-shadow: 0px 1px 0px rgba(120, 200, 230, 0.6) inset;color: #FFF;"type="button" value="Done" onClick="self.close();">&emsp;<a href="#" onclick="window.opener.mooauth_proceedToAttributeMapping();self.close();">Proceed To Attribute/Role Mapping</a></div>';
            exit();
        }

        if (!empty($username_attr))
            $username = mooauth_client_getnestedattribute($resourceOwner, $username_attr);

        if (empty($username) || "" === $username) {
            MOOAuth_Debug::mo_oauth_log('Username not received. Check your Attribute Mapping configuration.');
            exit('Username not received. Check your <b>Attribute Mapping</b> configuration.');
        }

        if (!is_string($username)) {
            MOOAuth_Debug::mo_oauth_log('Username is not a string. It is ' . mooauth_client_get_proper_prefix(gettype($username)));
            wp_die('Username is not a string. It is ' . mooauth_client_get_proper_prefix(gettype($username)));
        }

        $user = get_user_by("login", $username);

        if ($user) {
            $user_id = $user->ID;
        } else {
            $user_id = 0;
            if (mooauth_migrate_customers()) {
                $user = mooauth_looped_user($username);
            } else {
                $user = mooauth_handle_user_registration($username);
            }

        }
        if ($user) {
            wp_set_current_user($user->ID);
            wp_set_auth_cookie($user->ID);
            $user = get_user_by('ID', $user->ID);
            do_action('wp_login', $user->user_login, $user);

            $redirect_to = get_option('mo_oauth_redirect_url');

            if ($redirect_to == false) {
                $redirect_to = home_url();
            }

            wp_redirect($redirect_to);
            exit;
        }


    } else if (strpos($_SERVER['REQUEST_URI'], '/wp-json/moserver/token') === false && !isset($_SERVER['HTTP_X_REQUESTED_WITH']) && (strpos($_SERVER['REQUEST_URI'], "/oauthcallback") !== false || isset($_REQUEST['code']))) {
        if (session_id() == '' || !isset($_SESSION))
            session_start();

        if (!isset($_REQUEST['code'])) {
            if (isset($_REQUEST['error_description'])) {
                MOOAuth_Debug::mo_oauth_log('Authorization Response Recieved => ERROR : ' . sanitize_text_field($_REQUEST['error_description']));
                exit(esc_attr($_REQUEST['error_description']));
            } else if (isset($_REQUEST['error'])) {
                MOOAuth_Debug::mo_oauth_log('Authorization Response Recieved => ERROR : ' . sanitize_text_field($_REQUEST['error']));
                exit(esc_attr($_REQUEST['error']));
            }
            MOOAuth_Debug::mo_oauth_log('Authorization Response Recieved => ERROR : Invalid response');
            exit('Invalid response');
        } else {

            // exit from our control when user is already logged in. This it to prevent the issue with Ecwid Ecommerce plugin
//				if(is_user_logged_in() && !isset($_COOKIE['mo_oauth_test']) ) {
//				 	return;
//				}

            try {

                $currentappname = "";

                if (isset($_SESSION['appname']) && !empty($_SESSION['appname']))
                    $currentappname = sanitize_text_field($_SESSION['appname']);
                else if (isset($_REQUEST['state']) && !empty($_REQUEST['state'])) {
                    $currentappname = sanitize_text_field(base64_decode($_REQUEST['state']));
                }

                if (empty($currentappname)) {
                    MOOAuth_Debug::mo_oauth_log('ERROR : No request found for this application.');
                    exit('No request found for this application.');
                }

                $appslist = get_option('mo_oauth_apps_list');
                $username_attr = "";
                $currentapp = false;
                foreach ($appslist as $key => $app) {
                    if ($key == $currentappname) {
                        $currentapp = $app;
                        if (isset($app['username_attr'])) {
                            $username_attr = $app['username_attr'];
                        } else if (isset($app['email_attr'])) {
                            mooauth_update_email_to_username_attr($currentappname);
                            $username_attr = $app['email_attr'];
                        }
                    }
                }

                if (!$currentapp) {
                    MOOAuth_Debug::mo_oauth_log('Authorization Response Recieved => ERROR : Application not configured.');
                    exit('Application not configured.');
                }
                $resourceownerdetailsurl = $currentapp['resourceownerdetailsurl'];
                $mo_oauth_handler = new MOOAuth_Hanlder();
                MOOAuth_Debug::mo_oauth_log('Authorization Response Received');

                if (isset($currentapp['apptype']) && $currentapp['apptype'] == 'openidconnect' && $currentappname !== $singpassappname) {
                    // OpenId connect

                    MOOAuth_Debug::mo_oauth_log('OpenId Flow');

                    if (isset($_REQUEST['id_token'])) {
                        $idToken = sanitize_text_field($_REQUEST['id_token']);
                    } else {
                        if (!isset($currentapp['send_headers']))
                            $currentapp['send_headers'] = false;
                        if (!isset($currentapp['send_body']))
                            $currentapp['send_body'] = false;
                        $tokenResponse = $mo_oauth_handler->getIdToken(
                            $currentapp['accesstokenurl'],
                            'authorization_code',
                            $currentapp['clientid'],
                            $currentapp['clientsecret'],
                            sanitize_text_field($_GET['code']),
                            $currentapp['redirecturi'],
                            $currentapp['send_headers'],
                            $currentapp['send_body']
                        );

                        $idToken = isset($tokenResponse["id_token"]) ? $tokenResponse["id_token"] : $tokenResponse["access_token"];

                    }

                    if (!$idToken) {
                        MOOAuth_Debug::mo_oauth_log('Token Response Recieved => ERROR : Invalid token received.');
                        exit('Invalid token received.');
                    } else {
                        MOOAuth_Debug::mo_oauth_log('ID Token => ');
                        MOOAuth_Debug::mo_oauth_log($idToken);
                        $resourceOwner = $mo_oauth_handler->getResourceOwnerFromIdToken($idToken);
                        MOOAuth_Debug::mo_oauth_log('Resource Owner Response => ' . json_encode($resourceOwner));
                    }

                } else {
                    // echo "OAuth";

                    MOOAuth_Debug::mo_oauth_log('OAuth Flow');

                    $accessTokenUrl = $currentapp['accesstokenurl'];
                    $accessToken = "";
                    $tokenResponse = "";
                    if (!isset($currentapp['send_headers']))
                        $currentapp['send_headers'] = false;
                    if (!isset($currentapp['send_body']))
                        $currentapp['send_body'] = false;

                    if ($currentappname === $singpassappname) {
                        try {
                            if (class_exists('MosingpassPlugin')) {
                                MosingpassPlugin::writeLog($accessTokenUrl, 'OAuth Flow accessTokenUrl');
                                $accessToken = $tokenResponse = MosingpassPlugin::getSingPassAuthorizationToken($currentapp);
                            }
                        } catch (Exception $e) {

                        }
                    } else {
                        $accessToken = $mo_oauth_handler->getAccessToken($accessTokenUrl, 'authorization_code', $currentapp['clientid'], $currentapp['clientsecret'], sanitize_text_field($_GET['code']), $currentapp['redirecturi'], $currentapp['send_headers'], $currentapp['send_body']);
                    }

                    if (!$accessToken) {
                        MOOAuth_Debug::mo_oauth_log('Access Token Response => ERROR : Invalid token received.');
                        exit('Invalid token received.');
                    }


                    if (substr($resourceownerdetailsurl, -1) == "=") {
                        $resourceownerdetailsurl .= $accessToken;
                    }
                    MOOAuth_Debug::mo_oauth_log('Token Response Recieved => ' . $accessToken);
                    MOOAuth_Debug::mo_oauth_log('Token Response Recieved => ' . $tokenResponse);
                    MOOAuth_Debug::mo_oauth_log('resourceownerdetailsurl => ' . $resourceownerdetailsurl, 'resourceownerdetailsurl');
                    if ($currentappname === $singpassappname) {
                        try {
                            if (class_exists('MosingpassPlugin')) {
                                $idToken = isset($tokenResponse["id_token"]) ? $tokenResponse["id_token"] : null;
                                if (!$idToken) {
                                    MOOAuth_Debug::mo_oauth_log('Token Response Recieved => ERROR : Invalid token received.');
                                    exit('Invalid token received.');
                                } else {
                                    MOOAuth_Debug::mo_oauth_log('ID Token => ');
                                    MOOAuth_Debug::mo_oauth_log($idToken);
                                    $resourceOwner = MosingpassPlugin::getResourceOwnerFromIdToken($idToken);
                                    MOOAuth_Debug::mo_oauth_log('Resource Owner Response => ' . json_encode($resourceOwner));

                                    if ($resourceOwner) {
                                        $accessToken = isset($tokenResponse["access_token"]) ? $tokenResponse["access_token"] : null;
                                        if (!$accessToken) {
                                            MOOAuth_Debug::mo_oauth_log('Token Response Recieved => ERROR : Invalid token received.');
                                            exit('Invalid token received.');
                                        } else {
                                            MOOAuth_Debug::mo_oauth_log('Access Token => ');
                                            MOOAuth_Debug::mo_oauth_log($accessToken);
                                            $userInfo = MosingpassPlugin::getUserInfo($accessToken, $resourceOwner);
                                            MOOAuth_Debug::mo_oauth_log('User Info Response => ' . json_encode($userInfo));
                                        }
                                    }
                                }
                            }
                        } catch (Exception $e) {

                        }
                    } else {
                        $resourceOwner = $mo_oauth_handler->getResourceOwner($resourceownerdetailsurl, $accessToken);
                    }

                    MOOAuth_Debug::mo_oauth_log('Resource Owner Response => ');
                    MOOAuth_Debug::mo_oauth_log($resourceOwner);
                }

                $username = "";
                update_option('mo_oauth_attr_name_list', $resourceOwner);
                //TEST Configuration
                if (isset($_COOKIE['mo_oauth_test']) && $_COOKIE['mo_oauth_test']) {
                    setcookie("mo_oauth_test", false, null, null, null, true, true);
                    echo '<div style="font-family:Calibri;padding:0 3%;">';
                    echo '<style>table{border-collapse:collapse;}th {background-color: #eee; text-align: center; padding: 8px; border-width:1px; border-style:solid; border-color:#212121;}tr:nth-child(odd) {background-color: #f2f2f2;} td{padding:8px;border-width:1px; border-style:solid; border-color:#212121;}</style>';
                    echo "<h2>" . esc_html__('Test Configuration', 'miniorange-login-with-eve-online-google-facebook') . "</h2><table><tr><th>" . esc_attr__('Attribute Name', 'miniorange-login-with-eve-online-google-facebook') . "</th><th>" . esc_attr__('Attribute Value', 'miniorange-login-with-eve-online-google-facebook') . "</th></tr>";
                    mooauth_client_testattrmappingconfig("", $resourceOwner);
                    $app = array_values(get_option('mo_oauth_apps_list'))[0];
                    if (isset($app['username_attr']))
                        $username_attr_mapping = $app['username_attr'];
                    else
                        $username_attr_mapping = false;
                    echo "</table>";
                    echo '<div style="padding: 10px;"></div><input style="padding:1%;width:100px;background: #0091CD none repeat scroll 0% 0%;cursor: pointer;font-size:15px;border-width: 1px;border-style: solid;border-radius: 3px;white-space: nowrap;box-sizing: border-box;border-color: #0073AA;box-shadow: 0px 1px 0px rgba(120, 200, 230, 0.6) inset;color: #FFF;"type="button" value="Done" onClick="self.close();">&emsp;';
                    echo '</div>';

                    exit();
                }

                if (!empty($username_attr))
                    $username = mooauth_client_getnestedattribute($resourceOwner, $username_attr); //$resourceOwner[$email_attr];

                if (empty($username) || "" === $username) {
                    MOOAuth_Debug::mo_oauth_log('Username not received. Check your Attribute Mapping configuration.');
                    exit('Username not received. Check your <b>Attribute Mapping</b> configuration.');
                }
                try {
                    $user = get_user_by("login", $username);
                } catch (Exception $e) {

                }
                $after_login_url = get_option(MosingpassPlugin::AFTER_LOGIN_URL);
                if ($user) {
                    $user_id = $user->ID;
                    MosingpassPlugin::writeLog($after_login_url, 'after_login_url');
                } else {
                    $user_id = 0;
                    $create_new_user = boolval(get_option(MosingpassPlugin::CREATE_NEW_USER));
                    $redirect_to = get_option(MosingpassPlugin::ADD_NEW_USER_FORM);
                    MosingpassPlugin::writeLog($create_new_user, 'create_new_user');
                    MosingpassPlugin::writeLog($redirect_to, 'redirect_to');
                    if (!$create_new_user) {
                        MosingpassPlugin::writeLog($create_new_user, 'create_new_user');
                        if ($redirect_to) {
                            wp_redirect($redirect_to);
                            exit;
                        } else {
                            $redirect_to = home_url();
                            wp_redirect($redirect_to);
                            exit;
                        }
                    }

                    if (mooauth_migrate_customers()) {
                        try {
                            $user = mooauth_looped_user($username);
                        } catch (Exception $e) {

                        }
                    } else {
                        try {
                            $user = mooauth_handle_user_registration($username);
                        } catch (Exception $e) {

                        }
                    }
                }
                if ($user) {
                    wp_set_current_user($user->ID);
                    wp_set_auth_cookie($user->ID);
                    $redirect_to = get_option('mo_oauth_redirect_url');
                    if (has_action('mo_hack_login_session_redirect')) {
                        $token = mooauth_gen_rand_str();
                        $password = mooauth_gen_rand_str();
                        $config = array(
                            "user_id" => $user->ID,
                            "user_password" => $password
                        );
                        set_transient($token, $config);
                        do_action("mo_hack_login_session_redirect", $user, $password, $token, $redirect_to);
                    }
                    $user = get_user_by('ID', $user->ID);
                    do_action('wp_login', $user->user_login, $user);

                    if ($redirect_to == false) {
                        if ($after_login_url) {
                            $redirect_to = $after_login_url;
                        } else {
                            $redirect_to = home_url();
                        }
                    }

                    wp_redirect($redirect_to);
                    exit;
                }


            } catch (Exception $e) {

                // Failed to get the access token or user details.

                MOOAuth_Debug::mo_oauth_log($e->getMessage());
                exit($e->getMessage());

            }

        }

    }
}

function mooauth_handle_user_registration($username)
{
    $random_password = wp_generate_password(10, false);

    if (strlen($username) > 60) {
        MOOAuth_Debug::mo_oauth_log('ERROR : The username received has a length greater than 60 characters.');
        wp_die($message = 'You are not allowed to login. Please contact your administrator');
    }
    if (class_exists('MosingpassPlugin')) {
        try {
            if (class_exists('MosingpassPlugin')) {
                $user_id = wp_create_user($username, $random_password, $username . "@octopus8.com");
            }
        } catch (Exception $e) {
            $user_id = wp_create_user($username, $random_password, "test@octopus8.com");
        }
    } else {
        $user_id = wp_create_user($username, $random_password);
    }
    $user = get_user_by('login', $username);
    wp_update_user(array('ID' => $user_id));
    return $user;
}

//here entity is corporation, alliance or character name. The administrator compares these when user logs in
function mooauth_check_validity_of_entity($entityValue, $entitySessionValue, $entityName)
{

    $entityString = $entityValue ? $entityValue : false;
    $valid_entity = false;
    if ($entityString) {            //checks if entityString is defined
        if (strpos($entityString, ',') !== false) {            //checks if there are more than 1 entity defined
            $entity_list = array_map('trim', explode(",", $entityString));
            foreach ($entity_list as $entity) {            //checks for each entity to exist
                if ($entity == $entitySessionValue) {
                    $valid_entity = true;
                    break;
                }
            }
        } else {        //only one entity is defined
            if ($entityString == $entitySessionValue) {
                $valid_entity = true;
            }
        }
    } else {            //entity is not defined
        $valid_entity = false;
    }
    return $valid_entity;
}

function mooauth_looped_user($temp_var)
{
    return mooauth_looped_redirect($temp_var);
}

function mooauth_client_testattrmappingconfig($nestedprefix, $resourceOwnerDetails, $tr_class_prefix = '')
{

    $username_value = "";
    foreach ($resourceOwnerDetails as $key => $resource) {
        if (is_array($resource) || is_object($resource)) {
            if (!empty($nestedprefix))
                $nestedprefix .= ".";
            mooauth_client_testattrmappingconfig($nestedprefix . $key, $resource, $tr_class_prefix);
            $nestedprefix = rtrim($nestedprefix, ".");
        } else {
            echo '<tr class="' . esc_attr($tr_class_prefix) . 'tr">' . '<td class="' . esc_attr($tr_class_prefix) . 'td">';
            if (!empty($nestedprefix))
                $key = $nestedprefix . "." . $key;
            echo esc_html($key) . "</td>" . '<td class="' . esc_attr($tr_class_prefix) . 'td">' . esc_html($resource) . "</td></tr>";

            $appslist = get_option('mo_oauth_apps_list');
            $currentapp = null;
            $currentappname = null;
            if (is_array($appslist)) {
                foreach ($appslist as $currentappname => $currentapp) {
                    break;
                }
            }
            if (strpos($username_value, "username") === false) {
                if (strpos($key, "username") !== false)
                    $username_value = $key;
                else if (strpos($key, "email") !== false && filter_var($resource, FILTER_VALIDATE_EMAIL)) {
                    $username_value = $key;
                }
            }
        }
    }

    if (!isset($currentapp['username_attr']) && $username_value) {
        $currentapp['username_attr'] = $username_value;
        $appslist[$currentappname] = $currentapp;
        update_option('mo_oauth_apps_list', $appslist);
    }
}

function mooauth_client_getnestedattribute($resource, $key)
{
    if ($key === "")
        return "";

    $keys = explode(".", $key);
    if (sizeof($keys) > 1) {
        $current_key = $keys[0];
        if (isset($resource[$current_key]))
            return mooauth_client_getnestedattribute($resource[$current_key], str_replace($current_key . ".", "", $key));
    } else {
        $current_key = $keys[0];
        if (isset($resource[$current_key])) {
            return $resource[$current_key];
        }
    }
}

function mooauth_looped_redirect($ejhi)
{
    $user = mooauth_handle_user_registration($ejhi);
    return $user;
}

function mooauth_client_get_proper_prefix($type)
{
    $letter = substr($type, 0, 1);
    $vowels = ['a', 'e', 'i', 'o', 'u'];
    return (in_array($letter, $vowels)) ? ' an ' . $type : ' a ' . $type;
}

function mooauth_register_widget()
{
    register_widget('mooauth_widget');
}

function mooauth_client_is_ajax_request()
{
    return defined('DOING_AJAX') && DOING_AJAX;
}

function mooauth_client_is_rest_api_call()
{
    return strpos(sanitize_text_field($_SERVER['REQUEST_URI']), '/wp-json') == false;
}

function mooauth_gen_rand_str($length = 10)
{
    $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $characters_length = strlen($characters);
    $random_string = '';
    for ($i = 0; $i < $length; $i++) {
        $random_string .= $characters[rand(0, $characters_length - 1)]; // phpcs:ignore
    }
    return $random_string;
}

add_action('widgets_init', 'mooauth_register_widget');
add_action('init', 'mooauth_login_validate');
?>