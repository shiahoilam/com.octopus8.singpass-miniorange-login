<?php
  
class MOOAuth_Client_Admin_Addons {

  public static $all_addons = array(
        array(
          'tag' => 'page-restriction',
          'title' => 'Page & Post Restriction',
          'desc' => 'Allows to restrict access to WordPress pages/posts based on user roles and their login status, thereby preventing them from unauthorized access.',
          'img' => 'images/page-restriction.png',
          'link' => 'https://plugins.miniorange.com/wordpress-page-restriction',
          'in_allinclusive' => true,
        ),

        array(
          'tag' => 'discord',
          'title' => 'Discord Role Mapping',
          'desc' => 'Discord Role Mapping add-on helps you to get roles from your discord server and maps it to WordPress user while SSO.',
          'img' => 'images/discord.png',
          'link' => 'https://plugins.miniorange.com/discord-wordpress-single-sign-on-integration',
          'in_allinclusive' => true,
        ),

        array(
          'tag' => 'learndash',
          'title' => 'LearnDash Integration',
          'desc' => 'Integrates LearnDash with your IDP by mapping the users to LearnDash groups based on the attributes sent by your IDP.',
          'img' => 'images/learndash.png',
          'link' => 'https://plugins.miniorange.com/wordpress-learndash-integrator',
          'in_allinclusive' => true,
        ),

        array(
          'tag' => 'buddypress',
          'title' => 'BuddyPress Integrator',
          'desc' => 'Allows to integrate user information received from OAuth/OpenID Provider with the BuddyPress profile.',
          'img' => 'images/buddypress.png',
          'link' => 'https://plugins.miniorange.com/wordpress-buddypress-integrator',
          'in_allinclusive' => true,
        ),

        array(
          'tag' => 'scim',
          'title' => 'SCIM User Provisioning',
          'desc' => 'Allows user provisioning with SCIM standard. System for Cross-domain Identity Management is a standard for automating the exchange of user identity information between identity domains, or IT systems.',
          'img' => 'images/scim.png',
          'link' => 'https://plugins.miniorange.com/wordpress-user-provisioning',
          'in_allinclusive' => true,
        ),

        array(
          'tag' => 'session',
          'title' => 'SSO Session Management',
          'desc' => 'SSO session management add-on manages the login session time of your users based on their WordPress roles.',
          'img' => 'images/session.jpg',
          'link' => 'https://plugins.miniorange.com/sso-session-management',
          'in_allinclusive' => true,
        ),

        array(
          'tag' => 'login-form',
          'title' => 'Login Form Add-on',
          'desc' => 'Provides Login form for OAuth/OpenID login instead of just a button. It relies on OAuth/OpenID plugin to have Password Grant configured, and can be customized using custom CSS & JS.',
          'img' => 'images/login-form.png',
          'link' => 'https://plugins.miniorange.com/idp-login-form-plugin-for-sso',
          'in_allinclusive' => true,
        ),

        array(
          'tag' => 'media',
          'title' => 'Media Restriction',
          'desc' => 'miniOrange Media Restriction add-on restrict unauthorized users from accessing the media files on your WordPress site.',
          'img' => 'images/media.jpg',
          'link' => 'https://plugins.miniorange.com/wordpress-media-restriction',
          'in_allinclusive' => true,
        ),

        array(
          'tag' => 'member-login',
          'title' => 'Membership based Login',
          'desc' => "Redirect users to custom pages based on user's membership levels. Checks for the user's membership level at every login. Thus, any update on membership level doesn't affect redirection.",
          'img' => 'images/member-login.png',
          'link' => 'https://plugins.miniorange.com/wordpress-attribute-based-redirection-restriction',
          'in_allinclusive' => true,
        ),

        array(
          'tag' => 'attribute',
          'title' => 'Attribute Based Redirection',
          'desc' => 'ABR add-on helps you to redirect your users to different pages after they log into your site, based on the attributes sent by your Identity Provider.',
          'img' => 'images/attribute-icon.png',
          'link' => 'https://plugins.miniorange.com/wordpress-attribute-based-redirection-restriction',
          'in_allinclusive' => true,
        ),

        array(
          'tag' => 'fsso',
          'title' => 'Two Factor Authentication',
          'desc' => '2FA methods: Google Authenticator, OTP Over SMS, OTP Over Email, Email Verification & miniOrange methods, with Unlimited Users & Multisite support, Website Security features.',
          'img' => 'images/fsso.png',
          'link' => 'https://plugins.miniorange.com/2-factor-authentication-for-wordpress',
          'in_allinclusive' => false,
        ),

        array(
          'tag' => 'jwetoken',
          'title' => 'SSO Into Multiple Apps',
          'desc' => 'Set up SSO using JWE BASED COOKIE TECHNIQUE, which allow users to perform SSO into multiple applications without entering the credentials again if they are hosted on the same domain/subdomain.',
          'img' => 'images/jwe_token.jpg',
          'link' => 'https://plugins.miniorange.com/sso-in-wordpress-and-applications-using-jwe-token-in-cookie',
          'in_allinclusive' => false,
        ),

        array(
          'tag' => 'profile_pic',
          'title' => 'Profile Picture Add-on',
          'desc' => 'Maps raw image data or URL received from your Identity Provider into Gravatar for the user.',
          'img' => 'images/profile_pic.png',
          'link' => 'https://plugins.miniorange.com/wordpress-profile-picture-map',
          'in_allinclusive' => false,
        ),

        array(
          'tag' => 'login-audit',
          'title' => 'SSO Login Audit',
          'desc' => 'SSO Login Audit captures all the SSO users and will generate the reports.',
          'img' => 'images/report.png',
          'link' => 'https://plugins.miniorange.com/wordpress-sso-login-audit',
          'in_allinclusive' => true,
        ),

        array(
          'tag' => 'azure',
          'title' => 'Forgot/Reset Password Policy Add-on',
          'desc' => 'Enables the the Forgot Password option provided on Azures Login page using the Azure Password Reset policy while SSO into WordPress.',
          'img' => 'images/azure.png',
          'link' => 'https://plugins.miniorange.com/self-service-reset-password-for-azure-active-directory-b2c',
          'in_allinclusive' => false,
        ),

      );

  public static $RECOMMENDED_ADDONS_PATH = array(

        "learndash"     =>  "sfwd-lms/sfwd_lms.php",
        "buddypress"    =>  "buddypress/bp-loader.php",
        "memberpress"   =>  "memberpress/memberpress.php",
    );
      

  public static function addons() {
      self::addons_page();
  }
    
    public static function addons_page() {

      $addons_recommended = array();
      
?>

<style>
.outermost-div {
  color: #424242;
  font-family: Open Sans!important;
  font-size: 14px;
  line-height: 1.4;
  letter-spacing: 0.3px;
}

.column_container {
  position: relative;
  box-sizing: border-box;
  margin-top: 20px;
  border-color: 1px solid red;
  z-index: 1000;
}  

.column_container > .column_inner {
  
  box-sizing: border-box;
  padding-left: 15px;
  padding-right: 10px;
  width: 100%;
  margin-right: 1px;
  font-family: Verdana, Arial, Helvetica, sans-serif;
  border-radius: 15px;
} 

.benefits-outer-block{
  padding-left: 1em;
  padding-right: 3em;
  padding-top: 3px;
  width: 85%;
  margin: 0;
  padding-bottom: 1em;
  background:#fff;
  height:250px;
  overflow: hidden;
  box-shadow: 0 5px 10px rgba(0,0,0,.20);
  border-radius: 5px;
}

.benefits-icon {
  font-size: 25px;
  padding-top: 6px;
  padding-right: 8px;
  padding-left: 8px;
  border-radius: 3px;
  padding-bottom: 5px;
  background: #1779ab;
  color: #fff;
}

.mo_2fa_addon_button{
  margin-top: 3px !important;
}

.mo_float-container {
    border: 1px solid #fff;
    padding-bottom: 70px;
   padding-top: 10px;
   padding-left: 1px;
   padding-right: 2px;
   
   width: 246px;
}

.mo_float-child {
    width: 17%;
    float: left;
    padding: 1px;
    padding-right: 0px;
    padding-left: 0px;
    height: 50px;
}  

.mo_float-child2{

    width: 78%;
    float: left;
    padding-left: 0px;
    padding-top:0px;
    height: 50px;
    font-weight: 700;
}

.mo_oauth_btn{
  margin: 0;
  position: absolute;
  bottom: 10px;
  left: 50%;
  -ms-transform: translateX(-50%);
  transform: translateX(-50%);
  display: inline-box;
  line-height: 1.42857143;
  text-align: center;
  white-space: nowrap;
  vertical-align: middle;
  touch-action: manipulation;
  cursor: pointer;
  user-select: none;
  background-image: none;
}


.mo_oauth_know_more_button{
  border-radius: 5px;
  font-weight: 600;
  margin: 0.5em 0.5em 0 0;
  font-size: 12px;
  padding: 0.4rem 1rem;
  border: solid 3px #012970;
  background-origin: border-box;
  box-shadow: 2px 1000px 1px #fff inset;
  transition: all 0.5s ease-out;
}
.mo_oauth_know_more_button:hover{
  box-shadow: 2px 1000px 1px #012970 inset;
}


h5 {
  font-weight: 700;
  font-size: 16px;
  line-height: 20px;
  text-transform: none;
  letter-spacing: 0.5px;
}

a {
  text-decoration: none;
  color: #585858;
  transition: all 0.5s ease-out;
}
 a:hover{
  color: #fff;
}

.mo_oauth_addon_headline a {
  text-decoration: none;
  color: #585858;
}

 
@media (min-width: 768px) {
  .grid_view {
    width: 33%;
    float: left;
  }
  .row-view {
    width: 100%;
    position: relative;
    display: inline-block;
  }
}

/*Content Animation*/
@keyframes fadeInScale {
  0% {
    transform: scale(0.9);
    opacity: 0;
  }
  
  100% {
    transform: scale(1);
    opacity: 1;
  }
}
</style>
<input type="hidden" value="<?php echo esc_attr( mooauth_is_customer_registered() );?>" id="mo_customer_registered_addon">

<a  id="mobacktoaccountsetup_addon" style="display:none;" href="<?php echo esc_attr( add_query_arg( array( 'tab' => 'account' ), esc_attr( sanitize_text_field( htmlentities(wp_unslash($_SERVER['REQUEST_URI'] ) ) ) ) ) ); ?>">Back</a>

<form style="display:none;" id="loginform_addon"
              action="<?php echo esc_attr( get_option( 'host_name' ) ) . '/moas/login'; ?>"
              target="_blank" method="post">
            <?php wp_nonce_field( 'mo_oauth_loginform_addon_nonce', 'mo_oauth_loginform_addon_field' ); ?>
            <input type="email" name="username" value="<?php echo esc_attr( get_option( 'mo_oauth_admin_email' ) ); ?>"/>
            <input type="text" name="redirectUrl"
                   value="<?php echo "https://plugins.miniorange.com/go/oauth-2fa-buy-now-payment"; ?>"/>
            <input type="text" name="requestOrigin" id="requestOrigin"/>
</form>
  
  <?php
  foreach (MOOAuth_Client_Admin_Addons::$RECOMMENDED_ADDONS_PATH as $key => $value) {
    if(is_plugin_active($value)){
      $addon = $key;
      $addons_recommended[$addon] = $addon;
    }
  }

  if(sizeof($addons_recommended)>0){ ?>
    <div class="mo_table_layout">
  <b><p style="padding-left: 15px;font-size: 20px;"><?php esc_attr_e('Recommended Add-ons for you:','miniorange-login-with-eve-online-google-facebook'); ?></p></b>
    <div class="outermost-div" style="background-color:#f7f7f7;opacity:1; ">
    <div class="row-view">
    <?php
     foreach ($addons_recommended as $key => $value)
      MOOAuth_Client_Admin_Addons::get_single_addon_cardt($value);
  }

    ?>
  </div>
</div>
</div>

<div class="mo_table_layout">
  <b><p style="padding-left: 15px;font-size: 20px;margin-top: 10px; margin-bottom: 10px;">Check out our add-ons :</p></b>
<div class="outermost-div" style="background-color:#f7f7f7;opacity:1;">

  <?php

  $available_addons = array();
  foreach (MOOAuth_Client_Admin_Addons::$all_addons as $key => $value) {
    # code...
    if(!array_search($value['tag'], $addons_recommended))
      array_push($available_addons, $value['tag']);
  }

  $all_addons = MOOAuth_Client_Admin_Addons::$all_addons;
  $total_addons = sizeof($available_addons);
    
    for ($i=0; $i < $total_addons; $i++) { ?>
      <div class="row-view">
        <?php 
        MOOAuth_Client_Admin_Addons::get_single_addon_cardt($available_addons[$i]);
        if($i+1 >= $total_addons)
          break;
        MOOAuth_Client_Admin_Addons::get_single_addon_cardt($available_addons[$i+1]);
        $i++;
        if($i+1 >= $total_addons)
          break;
        MOOAuth_Client_Admin_Addons::get_single_addon_cardt($available_addons[$i+1]);
        $i++;
        ?>
      </div> 
    <?php 
  }
  ?>
</div></div>


<script type="text/javascript">
   function upgradeform(planType) {
                if(planType === "") {
                  
                    location.href = "../../../../miniorange-login-with-eve-online-google-facebook/";
                    return;
                } else {
                    
                    jQuery('#requestOrigin').val(planType);
                    if(jQuery('#mo_customer_registered_addon').val()==1)
                      {
                        jQuery('#loginform_addon').submit();
                       
                    }
                    else{
                        location.href = jQuery('#mobacktoaccountsetup_addon').attr('href');
                    }
                }

            }
</script>
<?php
    }

    public static function get_single_addon_cardt($tag){
      foreach (MOOAuth_Client_Admin_Addons::$all_addons as $key => $value) {
        if(strpos( $value['tag'], $tag ) !== false){
          $addon = $value;
          break;
        }
      }
      if(isset($addon)){
    ?>
      <div class="grid_view column_container" style="border-radius: 5px;">
        <div class="column_inner" style="border-radius: 5px;">
          <div class="row benefits-outer-block">
            <div class="mo_float-container">
                <div class="mo_float-child" style="margin-left: 0px;padding-left: 0px;"> 
                  <img src="<?php echo esc_url( plugins_url($addon['img'], __FILE__) ) ?>" width="45px" height="48px">
                </div>
            <div class="mo_float-child2">
            <div class="mo_oauth_addon_headline"><strong><p style="font-size: 20px;margin: 1px;padding-left: 7px;line-height: 120%;font-weight: 600;font-family: Verdana, Arial, Helvetica, sans-serif;" ><a  href= "<?php echo isset($addon['link']) ? esc_attr( $addon['link'] ) : '';?>" target="_blank" rel="noopener"><?php echo esc_html( $addon['title'] ) ?></a></p></strong></div>
          </div>
          </div>
          <p style="text-align: center;font-family: Verdana, Arial, Helvetica, sans-serif;font-size: 11px;"><?php echo esc_html( $addon['desc'] ) ?></p>
          <a class="mo_oauth_btn mo_oauth_know_more_button" href= "<?php echo esc_url( $addon['link']) ?>" target="_blank" >Know More</a> 
          </div>
        </div>
      </div>
        <?php
      }
    }
}
?>