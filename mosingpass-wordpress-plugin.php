<?php
require_once dirname(__FILE__) . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'autoload.php';

// If this file is called directly, abort.

use Jose\Component\Core\{
    AlgorithmManager,
    JWK};
use Jose\Component\Encryption\{
    Algorithm\KeyEncryption\ECDHESA256KW,
    Algorithm\ContentEncryption\A256CBCHS512,
    Compression\CompressionMethodManager,
    Compression\Deflate,
    JWELoader,
    JWEDecrypter,
    Serializer\CompactSerializer as EncryptionCompactSerializer,
    Serializer\JWESerializerManager
};

use Jose\Component\Signature\{
    Algorithm\ES256,
    JWSBuilder,
    Serializer\CompactSerializer as SignatureCompactSerializer};

if (!defined('ABSPATH')) {
    die;
}

include 'mosingpass-settings-page.php';

class MosingpassPlugin
{


    public const WRITE_LOG = "mosp_write_log";
    public const REDIRECT_URI = "mosp_redirect_uri";
    public const SINGPASS_AUTH_ENDPOINT = "mosp_singpass_auth_endpoint";
    public const SINGPASS_TOKEN_ENDPOINT = "mosp_singpass_token_endpoint";
    public const SINGPASS_OPENID_ENDPOINT = "mosp_singpass_openid_endpoint";
    public const SINGPASS_JWKS_ENDPOINT = "mosp_singpass_jwk_endpoint";
    public const APP_NAME = "mosp_app_name";
    public const PUBLIC_JWKS = "mosp_public_jwks";
    public const PRIVATE_JWKS = "mosp_private_jwks";
    public const PRIVATE_SIG_KEY = "mosp_private_sig_key";
    public const PRIVATE_ENC_KEY = "mosp_private_enc_key";
    public $plugin_name;
    private $settings_page;

    public function __construct()
    {
        $this->plugin_name = plugin_basename(__FILE__);
        $plugin_name = $this->plugin_name;
        add_action('admin_menu', array($this, 'addAdminSettings'));
        add_action('admin_init', array($this, 'createSettings'));
        $this->settings_page = new MosingpassPluginSettingsPage();
        add_action('rest_api_init', function () {
            register_rest_route('singpass/v1', '/jwks', array(
                'methods' => 'GET',
                'callback' => array($this, 'singpass_jwks'),
            ));
        });
        add_filter("plugin_action_links_$plugin_name", array($this, 'settings_link'));

        add_action('rest_api_init', function () {
            register_rest_route('singpass/v1', '/signin_oidc/', array(
                'methods' => 'GET',
                'callback' => array($this, 'oidc_signin_callback'),
            ));
        });

    }

    /**
     * @param array $headerbody
     * @return array
     */
    protected static function getNricUen(array $headerbody): array
    {
        $uen = $nric = "";
        if (array_key_exists(1, $headerbody)) {
            if (array_key_exists('sub', $headerbody[1])) {
                $stringwithnricuen = $headerbody[1]['sub'];
                $arraynricuen = explode(",", $stringwithnricuen);
                if (sizeof($arraynricuen) == 2) {
                    foreach ($arraynricuen as $nricuen) {
                        if (substr($nricuen, 0, 2) == "s=") {
                            $nric = substr($nricuen, 2);
                        }
                        if (substr($nricuen, 0, 2) == "u=") {
                            $uen = substr($nricuen, 2);
                        }
                    }
                }
                return ["nric" => $nric, "uen" => $uen];
            }
        }
        self::writeLog('Token Response Received => ERROR : Invalid response received from OAuth Provider. Contact your administrator for more details. ' . esc_html($headerbody));
        echo 'Invalid response received from OAuth Provider. Contact your administrator for more details.<br><br><b>Response : </b><br>' . esc_html($headerbody);
        return ["nric" => $nric, "uen" => $uen];
    }

    function settings_link($links)
    {
        $settings_page = MosingpassPluginSettingsPage::SETTINGS_PAGE;
        $settins_link = '<a href="options-general.php?page=' . $settings_page . '">Settings</a>';
        array_push($links, $settins_link);
        return $links;
    }

    function createSettings()
    {
        $this->settings_page->createSettings();
    }

    function addAdminSettings()
    {
        $this->settings_page->addAdminSettings();
    }

    function singpass_jwks()
    {
        echo get_option(self::PUBLIC_JWKS);
    }

    function oidc_signin_callback($params)
    {
        return $params;
    }

    /**
     * @return array
     */
    protected static function getJWKS(): array
    {
        $public_jwks = json_decode(get_option(self::PUBLIC_JWKS));
        self::writeLog($public_jwks, 'public_jwks');
        foreach ($public_jwks->{'keys'} as $public_jwk) {
            if (strcmp($public_jwk->{'use'}, 'sig') == 0) {
                $sig_kid = $public_jwk->{'kid'};
                $public_sig_jwk = json_decode(json_encode($public_jwk), true);
            }
            if (strcmp($public_jwk->{'use'}, 'enc') == 0) {
                $enc_kid = $public_jwk->{'kid'};
                $public_enc_jwk = json_decode(json_encode($public_jwk), true);
            }
        }

        $private_jwks = json_decode(get_option(self::PRIVATE_JWKS));
        self::writeLog($private_jwks, 'private_jwks');
        foreach ($private_jwks->{'keys'} as $private_jwk) {
            if (strcmp($private_jwk->{'use'}, 'sig') == 0) {
                $private_sig_jwk = json_decode(json_encode($private_jwk), true);
            }
            if (strcmp($private_jwk->{'use'}, 'enc') == 0) {
                $private_enc_jwk = json_decode(json_encode($private_jwk), true);
            }
        }
        self::writeLog($sig_kid, 'sig_kid');
        self::writeLog($enc_kid, 'enc_kid');
        self::writeLog($public_sig_jwk, 'sig_kid');
        self::writeLog($public_enc_jwk, 'enc_kid');
        self::writeLog($private_sig_jwk, 'sig_kid');
        self::writeLog($private_enc_jwk, 'enc_kid');

        return array($sig_kid, $public_sig_jwk, $enc_kid, $public_enc_jwk, $private_sig_jwk, $private_enc_jwk);
    }


    public static function writeLog($log, $log_header = "Some Function")
    {
        $log_header = $log_header . "\r\n";
        $log_message = (is_array($log) || is_object($log) ? print_r($log, true) : $log) . "\r\n";
        $log_time = '[' . date("F j, Y, g:i a e O") . ']' . "\r\n";
        $message = $log_time . $log_header . $log_message;
//        if (true === WP_DEBUG && true === WP_DEBUG_LOG) {
        $plugin_dir_path = plugin_dir_path(__FILE__);
        $pluginlog = $plugin_dir_path . 'debug.log';
        error_log($message, 3, $pluginlog);
    }

    /**
     * @param string $appname
     * @param $app
     */
    public static function loadSingPassTest(string $appname, $app): void
    {
        $state = base64_encode($appname);
        $nonce = $state;
        $authorizationUrl = $app['authorizeurl'];

        if (strpos($authorizationUrl, '?') !== false) {
            $authorizationUrl = $authorizationUrl . "&";
        } else {
            $authorizationUrl = $authorizationUrl . "?";
        }

        $clientid = $app['clientid'];
        $scope = $app['scope'] ? $app['scope'] : "openid";
        $redirect_uri = get_option(self::REDIRECT_URI);
        $authorizationUrl = $authorizationUrl .
            "client_id=" . $clientid .
            "&scope=" . $scope .
            "&redirect_uri=" . $redirect_uri .
            "&response_type=code" .
            "&state=" . $state .
            "&nonce=" . $nonce;;

        if (session_id() == '' || !isset($_SESSION))
            session_start();
        $_SESSION['oauth2state'] = $state;
        $_SESSION['appname'] = $appname;

        self::writeLog($authorizationUrl, 'Authorization Request');
        header('Location: ' . $authorizationUrl);
    }
//    }


    /**
     * @param bool $currentapp
     * @return string
     */
    public static function getSingPassAuthorizationToken($currentapp)
    {
        $accessToken = "";
        try {

            $code = $_GET['code'];
            $state = $_GET['state'];
            self::writeLog($code, 'code');
            self::writeLog($state, 'state');
//            self::writeLog($currentapp, 'currentapp');

            $tokenendpoint = $currentapp['accesstokenurl'];
            $singpass_client = $currentapp['clientid'];
            $redirect_uri = get_option(self::REDIRECT_URI);
            self::writeLog($redirect_uri, 'redirect_uri');

            list($sig_kid,
                $public_sig_jwk,
                $enc_kid,
                $public_enc_jwk,
                $private_sig_jwk,
                $private_enc_jwk) = self::getJWKS();

            $sig_private_jwk = new JWK($private_sig_jwk);
            self::writeLog($sig_private_jwk, 'sig_private_jwk');

            $algorithmManager = new AlgorithmManager([
                new ES256(),
            ]);
            self::writeLog($algorithmManager, 'algorithmManager');
            $jwsBuilder = new JWSBuilder($algorithmManager);

            $now = time();
            $payload = json_encode([
                'iss' => $singpass_client,
                "sub" => $singpass_client,
                'aud' => "https://stg-id.singpass.gov.sg",
                'iat' => $now,
                'exp' => $now + 60,
            ]);

            try {
                $jws = $jwsBuilder
                    ->create()// We want to create a new JWS
                    ->withPayload($payload)// We set the payload
                    ->addSignature($sig_private_jwk, [
                        'alg' => 'ES256',
                        "kid" => $sig_kid,
                        "typ" => "JWT"
                    ])// We add a signature with a simple protected header
                    ->build();
            } catch (Exception $e) {

            }
            self::writeLog($payload, 'Payload');
            self::writeLog($jws, 'jws');
            $serializer = new SignatureCompactSerializer(); // The serializer
            $client_assertion = $serializer->serialize($jws, 0);
            self::writeLog($client_assertion, 'ClientAssertion');

            $body = array(
                'code' => $code,
                'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion' => $client_assertion,
                'client_id' => $singpass_client,
                'scope' => 'openid',
                'grant_type' => 'authorization_code',
                'redirect_uri' => $redirect_uri
            );
            self::writeLog($body, 'Body');

            $headers = array(
                'Accept: application/json',
                'charset: ISO-8859-1',
                'Content-Type: application/x-www-form-urlencoded'
            );


            try {
                $response = wp_remote_post($tokenendpoint, array(
                    'method' => 'POST',
                    'timeout' => 45,
                    'redirection' => 5,
                    'httpversion' => '1.0',
                    'blocking' => true,
                    'headers' => $headers,
                    'body' => $body,
                    'cookies' => array(),
                    'sslverify' => false
                ));

                if (is_wp_error($response)) {
                    self::writeLog('Token Response Received => ERROR : Invalid response recieved while fetching token', 'is_wp_error');
                    self::writeLog('Invalid response recieved while fetching token', 'is_wp_error');
                    self::writeLog($response, 'is_wp_error');
                    wp_die(esc_html($response));
                }
                $response = $response['body'];
                self::writeLog('Token Response Received => ' . $response);
                if (!is_array(json_decode($response, true))) {
                    echo "<b>Response : </b><br>";
                    print_r(esc_html($response));
                    echo "<br><br>";
                    self::writeLog('Invalid response received.');
                    if (isset($response['body']))
                        self::writeLog($response['body']);
                    exit("Invalid response received.");
                }

                $content = json_decode($response, true);
                if (isset($content["error_description"])) {
                    self::writeLog('Token Response Received => ERROR : ' . $content["error_description"]);
                    exit(esc_html($content["error_description"]));
                } elseif (isset($content["error"])) {
                    self::writeLog('Token Response Received => ERROR : ' . $content["error"]);
                    exit(esc_html($content["error"]));
                }
            } catch (Exception $e) {

            }
            if (isset($content["access_token"])) {
                $accessToken = $content;
            } else {
                self::writeLog('Token Response Received => ERROR : Invalid response received from OAuth Provider. Contact your administrator for more details. ' . esc_html($response));
                echo 'Invalid response received from OAuth Provider. Contact your administrator for more details.<br><br><b>Response : </b><br>' . esc_html($response);
            }
        } catch
        (Exception $e) {

        }

        return $accessToken;
    }

    /**
     * @param $idToken
     * @return mixed
     */

    public static function getResourceOwnerFromIdToken($token)
    {
        //credentials part
        list($sig_kid,
            $public_sig_jwk,
            $enc_kid,
            $public_enc_jwk,
            $private_sig_jwk,
            $private_enc_jwk) = self::getJWKS();
        $encryption_serializer = new EncryptionCompactSerializer(); // The serializer
        $encryptionSerializerManager = new JWESerializerManager([
            $encryption_serializer,
        ]);
        $parser_url = "http://localhost:5000/parser";
        $body = array(
            'key' => $private_enc_jwk,
            'jwt' => $token
        );
        $headers = [
            'Accept: application/json',
            'charset: UTF-8',
            'Content-Type: application/json',
        ];

        try {
            $jwe = $encryption_serializer->unserialize($token);
            self::writeLog($jwe, 'JWE');
        } catch (Exception $e) {
            print('nonserializable with deserialized_JWE');
        }


        $keyEncryptionAlgorithmManager = new AlgorithmManager([
            new ECDHESA256KW(),
        ]);

        $contentEncryptionAlgorithmManager = new AlgorithmManager([
            new A256CBCHS512(),
        ]);

        $compressionMethodManager = new CompressionMethodManager([
            new Deflate(),
        ]);

        $jweDecrypter = new JWEDecrypter(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
            $compressionMethodManager
        );

        $public_enc_JWK = new JWK($public_enc_jwk);
        $private_enc_JWK = new JWK($private_enc_jwk);

        if ($jweDecrypter->decryptUsingKey($jwe, $private_enc_JWK, 0)) {
            $success_key = $private_enc_JWK;
        } else {
            self::writeLog('unsuccess', 'jweDecrypter->$private_enc_JWK');
        }

        $jweLoader = new JWELoader(
            $encryptionSerializerManager,
            $jweDecrypter,
            null
        );
        $unencrypted_payload = "";

        try {
            $jw_decrypted_response = $jweLoader->loadAndDecryptWithKey($token,
                $success_key,
                $recipient);
            $unencrypted_payload = $jw_decrypted_response->getPayload();
            self::writeLog($unencrypted_payload, 'success_key');
        } catch (Exception $e) {
            print('nonserializable with public_enc_JWK');
        }
        $headerbody = self::getHeaderPayloadFromIdToken($unencrypted_payload);
        return self::getNricUen($headerbody);
    }

    public static function getHeaderPayloadFromIdToken($id_token)
    {
        $id_array = explode(".", $id_token);
        if (isset($id_array[1])) {
            $id_body = base64_decode(str_pad(strtr($id_array[1], '-_', '+/'), strlen($id_array[1]) % 4, '=', STR_PAD_RIGHT));
            if (is_array(json_decode($id_body, true))) {
                $body = json_decode($id_body, true);
            }
            $id_header = base64_decode(str_pad(strtr($id_array[0], '-_', '+/'), strlen($id_array[0]) % 4, '=', STR_PAD_RIGHT));
            if (is_array(json_decode($id_header, true))) {
                $header = json_decode($id_header, true);
            }
            if ($body && $header) {
                return [$header, $body];
            }
        }
        MOOAuth_Debug::mo_oauth_log('Invalid response received while fetching Id token from the Resource Owner. Id_token : ' . esc_html($id_token));
        echo 'Invalid response received.<br><b>Id_token : </b>' . esc_html($id_token);
        exit;
    }


}

$mosingpassPlugin = new MosingpassPlugin();

?>