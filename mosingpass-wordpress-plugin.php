<?php

require_once dirname(__FILE__) . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'autoload.php';

// If this file is called directly, abort.

use Jose\Component\Core\{
    AlgorithmManager,
    JWK
};
use Jose\Component\Encryption\{
    Algorithm\KeyEncryption\ECDHESA256KW,
    Algorithm\ContentEncryption\A256CBCHS512,
    Algorithm\ContentEncryption\A256GCM,
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
    JWSVerifier,
    Serializer\CompactSerializer as SignatureCompactSerializer,
    Serializer\JWSSerializerManager,
    JWSLoader
};

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
    public const SINGPASS_USERINFO_ENDPOINT = "mosp_singpass_userinfo_endpoint";
    public const SINGPASS_OPENID_ENDPOINT = "mosp_singpass_openid_endpoint";
    public const SINGPASS_JWKS_ENDPOINT = "mosp_singpass_jwk_endpoint";
    public const APP_NAME = "mosp_app_name";
    public const SHOW_QR = "mosp_show_qr";
    public const CREATE_NEW_USER = "mosp_create_new_user";
    public const ADD_NEW_USER_FORM = "mosp_add_new_user_form";
    public const AFTER_LOGIN_URL = "mosp_after_login_url";
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
        $show_qr_code = get_option(MosingpassPlugin::SHOW_QR);
        if ($show_qr_code) {
            add_action('login_head', array($this, 'qr_code_scripts'));
        }

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
        return json_decode(get_option(self::PUBLIC_JWKS), true); // Decodes JSON for WordPress response
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
            "&nonce=" . $nonce;
        ;

        if (session_id() == '' || !isset($_SESSION))
            session_start();
        $_SESSION['oauth2state'] = $state;
        $_SESSION['nonce'] = $nonce;
        $_SESSION['appname'] = $appname;
        $_SESSION['client_id'] = $app['clientid'];

        self::writeLog($authorizationUrl, 'Authorization Request');
        header('Location: ' . $authorizationUrl);
    }

    public static function isJWE($token)
    {
        // Split the token by '.' and count the segments
        $parts = explode('.', $token);
        self::writeLog($parts, "Split Parts");
        return count($parts) === 5;
    }

    /**
     * Retrieve and cache JWKS with automatic cache invalidation and re-fetch on verification failure.
     * @return array
     */
    protected static function fetchJWKSWithCache(): array
    {
        $jwks_cache_key = 'mosingpass_jwks_cache';
        $cached_jwks = get_transient($jwks_cache_key);

        if ($cached_jwks) {
            // If JWKS is cached, return it directly
            self::writeLog("Retrieved JWKS from cache");
            return $cached_jwks;
        }

        // Fetch the JWKS from the endpoint if not cached
        $singpass_jwks_url = get_option(self::SINGPASS_JWKS_ENDPOINT);
        $response = wp_remote_get($singpass_jwks_url);

        if (is_wp_error($response)) {
            self::writeLog('Error fetching JWKS: ' . $response->get_error_message());
            return [];
        }

        $jwks_data = json_decode(wp_remote_retrieve_body($response), true);

        if (!isset($jwks_data['keys'])) {
            self::writeLog('Invalid JWKS data received.');
            return [];
        }

        // Cache JWKS for 1 hour (3600 seconds)
        set_transient($jwks_cache_key, $jwks_data['keys'], HOUR_IN_SECONDS);

        self::writeLog('Fetched JWKS and cached it.');
        return $jwks_data['keys'];
    }

    /**
     * Retrieve the JWK for a given kid from cached or refreshed JWKS.
     * @param string $kid
     * @return JWK|null
     */
    public static function getKeyForKid($kid): JWK|null
    {
        $jwks_keys = self::fetchJWKSWithCache();

        // Find the correct key with the matching kid
        foreach ($jwks_keys as $key) {
            if ($key['kid'] === $kid) {
                return new JWK($key);
            }
        }

        // If key not found, invalidate cache, re-fetch JWKS, and try again
        delete_transient('mosingpass_jwks_cache');
        self::writeLog("Key not found, cache deleted");
        $jwks_keys = self::fetchJWKSWithCache();

        foreach ($jwks_keys as $key) {
            if ($key['kid'] === $kid) {
                return new JWK($key);
            }
        }

        self::writeLog('Key with kid ' . $kid . ' not found after JWKS refresh.');
        return null;
    }

    public static function base_url($url)
    {
        $result = parse_url($url);
        return $result['scheme'] . "://" . $result['host'];
    }

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

            if ($state !== $_SESSION['oauth2state']) {
                self::writeLog('State does not match!', 'State Validation');
                exit('Invalid state parameter');
            }
            unset($_SESSION['oauth2state']);

            $tokenendpoint = $currentapp['accesstokenurl'];
            $singpass_client = $currentapp['clientid'];
            $singpass_uri = self::base_url(get_option(self::SINGPASS_OPENID_ENDPOINT));

            $redirect_uri = get_option(self::REDIRECT_URI);
            self::writeLog($redirect_uri, 'redirect_uri');

            list(
                $sig_kid,
                $public_sig_jwk,
                $enc_kid,
                $public_enc_jwk,
                $private_sig_jwk,
                $private_enc_jwk
            ) = self::getJWKS();

            $sig_private_jwk = new JWK($private_sig_jwk);
            self::writeLog($sig_private_jwk, log_header: 'sig_private_jwk');

            $algorithmManager = new AlgorithmManager([
                new ES256(),
            ]);
            self::writeLog($algorithmManager, 'algorithmManager');
            $jwsBuilder = new JWSBuilder($algorithmManager);

            $now = time();
            $payload = json_encode([
                "iss" => $singpass_client,
                "sub" => $singpass_client,
                'aud' => $singpass_uri,
                'iat' => $now,
                'exp' => $now + 90,
                'code' => $code
            ], JSON_UNESCAPED_SLASHES);

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
                self::writeLog($e->getMessage(), 'Payload');
                print ($e->getMessage());
            }
            self::writeLog($payload, 'Payload');
            self::writeLog($jws, 'jws');
            $serializer = new SignatureCompactSerializer(); // The serializer
            $client_assertion = $serializer->serialize($jws, 0);
            error_log("sig_kid value: " . print_r($sig_kid, true));
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
        list(
            $sig_kid,
            $public_sig_jwk,
            $enc_kid,
            $public_enc_jwk,
            $private_sig_jwk,
            $private_enc_jwk
        ) = self::getJWKS();

        $encryption_serializer = new EncryptionCompactSerializer(); // The serializer
        $encryptionSerializerManager = new JWESerializerManager([$encryption_serializer,]);
        $signature_serializer = new SignatureCompactSerializer();
        $signatureSerializerManager = new JWSSerializerManager([$signature_serializer,]);

        if (self::isJWE($token)) {
            try {
                $jwe = $encryption_serializer->unserialize($token);
                self::writeLog($jwe, 'JWE');
            } catch (Exception $e) {
                self::writeLog($e->getMessage(), 'nonserializable with deserialized_JWE');
            }
        }

        $keyEncryptionAlgorithmManager = new AlgorithmManager([
            new ECDHESA256KW(),
        ]);

        $contentEncryptionAlgorithmManager = new AlgorithmManager([
            new A256GCM(),
        ]);

        $compressionMethodManager = new CompressionMethodManager([
            new Deflate(),
        ]);

        $jweDecrypter = new JWEDecrypter(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
            $compressionMethodManager
        );

        $private_enc_JWK = new JWK($private_enc_jwk);

        if ($jwe) {
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
                $jw_decrypted_response = $jweLoader->loadAndDecryptWithKey(
                    $token,
                    $success_key,
                    $recipient
                );
                $unencrypted_payload = $jw_decrypted_response->getPayload();
                self::writeLog($unencrypted_payload, 'success_key');
            } catch (Exception $e) {
                print ('nonserializable with private_enc_JWK');
            }
            // $headerbody = self::getHeaderPayloadFromIdToken($unencrypted_payload);
            // return self::getNricUen($headerbody);
        } else {
            $unencrypted_payload = $token;
        }

        if ($unencrypted_payload) {
            try {
                $jws = $signatureSerializerManager->unserialize($unencrypted_payload);
                self::writeLog($jws, 'JWS');
            } catch (Exception $e) {
                self::writeLog($e->getMessage(), 'nonserializable with deserialized_JWS');
            }
        }

        $verifySignatureAlgorithmManager = new AlgorithmManager([
            new ES256(),
        ]);

        $jwsVerifier = new JWSVerifier(
            $verifySignatureAlgorithmManager,
        );

        $public_sig_JWK = new JWK($public_sig_jwk);

        // Extract `kid` from the token header
        $jwsHeader = json_decode(base64_decode(explode('.', $unencrypted_payload)[0]), true);
        $jws_kid = $jwsHeader['kid'];
        self::writeLog($jws_kid, 'JWS Header kid');

        // Retrieve Singpass's key using `kid`
        $singpass_key = self::getKeyForKid($jws_kid);
        self::writeLog($singpass_key, "Found kid");

        if ($jws) {
            if ($jwsVerifier->verifyWithKey($jws, $singpass_key, 0)) {
                $success_key = $singpass_key;
            } else {
                self::writeLog('unsuccess', 'jwsVerifier->$public_sig_JWK');
            }

            $jwsLoader = new JWSLoader(
                $signatureSerializerManager,
                $jwsVerifier,
                null,
            );

            self::writeLog($success_key);
            try {
                $jw_verified_response = $jwsLoader->loadAndVerifyWithKey(
                    $unencrypted_payload,
                    $success_key,
                    $signature,
                );
                $verified_payload = $jw_verified_response->getPayload();
                // print("Id token: Successfully verified JWS: " . $verified_payload);

                $decoded_payload = json_decode($verified_payload, true); // To convert string to JSON array
                $expectedIssuer = self::base_url(get_option(self::SINGPASS_TOKEN_ENDPOINT)); // Fetch the issuer URL from your settings

                if ($decoded_payload['iss'] !== $expectedIssuer) {
                    self::writeLog('ID Token validation failed: Invalid issuer', 'ID Token Validation');
                    exit('Invalid issuer in ID Token');
                }

                $clientId = $_SESSION['client_id'] ?? ''; // Fetch your client ID from session

                // Check if 'aud' is an array or a string
                if (is_array($decoded_payload['aud'])) {
                    if (!in_array($clientId, $decoded_payload['aud'])) {
                        self::writeLog('ID Token validation failed: Invalid audience', 'ID Token Validation');
                        exit('Invalid audience in ID Token(Arr)');
                    }
                } else {
                    if ($decoded_payload['aud'] !== $clientId) {
                        self::writeLog('ID Token validation failed: Invalid audience', 'ID Token Validation');
                        exit('Invalid audience in ID Token');
                    }
                }

                $sessionNonce = $_SESSION['nonce'] ?? '';

                if ($decoded_payload['nonce'] !== $sessionNonce) {
                    self::writeLog('ID Token validation failed: Nonce does not match', 'ID Token Validation');
                    exit('Invalid nonce in ID Token');
                }
                unset($_SESSION['nonce']);

                self::writeLog($decoded_payload, 'Decoded ID Token Payload');

                return $decoded_payload;
            } catch (Exception $e) {
                self::writeLog($e->getMessage());
                print ('nonserializable with public_sig_JWK');
            }
            // $headerbody = self::getHeaderPayloadFromIdToken($verified_payload);
            // return self::getNricUen($headerbody);
        }
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

    public static function getUserInfo($accessToken, $validatedIdToken)
    {
        $userinfo_endpoint = get_option(self::SINGPASS_USERINFO_ENDPOINT);

        $headers = [
            'Authorization' => 'Bearer ' . $accessToken,
            'Accept' => 'application/json',
        ];

        try {
            $response = wp_remote_get($userinfo_endpoint, [
                'method' => 'GET',
                'headers' => $headers,
                'timeout' => 45,
                'redirection' => 5,
                'httpversion' => '1.0',
                'blocking' => true,
                'sslverify' => false,
            ]);

            if (is_wp_error($response)) {
                self::writeLog('Userinfo Response Error: ' . $response->get_error_message());
                return new WP_Error('userinfo_error', 'Error fetching userinfo');
            }
            $jweToken = wp_remote_retrieve_body($response);

        } catch (Exception $e) {
            self::writeLog($e->getMessage(), 'Exception in Userinfo Endpoint');
            return new WP_Error('userinfo_exception', $e->getMessage());
        }

        list(
            $sig_kid,
            $public_sig_jwk,
            $enc_kid,
            $public_enc_jwk,
            $private_sig_jwk,
            $private_enc_jwk
        ) = self::getJWKS();

        $encryption_serializer = new EncryptionCompactSerializer(); // The serializer
        $encryptionSerializerManager = new JWESerializerManager([$encryption_serializer,]);
        $signature_serializer = new SignatureCompactSerializer();
        $signatureSerializerManager = new JWSSerializerManager([$signature_serializer,]);

        try {
            $jwe = $encryption_serializer->unserialize($jweToken);
            self::writeLog($jwe, 'JWE');
        } catch (Exception $e) {
            self::writeLog($e->getMessage(), 'nonserializable with deserialized_JWE');
        }

        $keyEncryptionAlgorithmManager = new AlgorithmManager([
            new ECDHESA256KW(),
        ]);

        $contentEncryptionAlgorithmManager = new AlgorithmManager([
            new A256GCM(),
        ]);

        $compressionMethodManager = new CompressionMethodManager([
            new Deflate(),
        ]);

        $jweDecrypter = new JWEDecrypter(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
            $compressionMethodManager
        );

        $private_enc_JWK = new JWK($private_enc_jwk);

        if ($jwe) {
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
                $jw_decrypted_response = $jweLoader->loadAndDecryptWithKey(
                    $jweToken,
                    $success_key,
                    $recipient
                );
                $unencrypted_payload = $jw_decrypted_response->getPayload();
                self::writeLog($unencrypted_payload, 'success_key');
            } catch (Exception $e) {
                print ('nonserializable with private_enc_JWK');
            }
            // $headerbody = self::getHeaderPayloadFromIdToken($unencrypted_payload);
            // return self::getNricUen($headerbody);
        }

        if ($unencrypted_payload) {
            try {
                $jws = $signatureSerializerManager->unserialize($unencrypted_payload);
                self::writeLog($jws, 'JWS');
            } catch (Exception $e) {
                self::writeLog($e->getMessage(), 'nonserializable with deserialized_JWS');
            }
        }

        $verifySignatureAlgorithmManager = new AlgorithmManager([
            new ES256(),
        ]);

        $jwsVerifier = new JWSVerifier(
            $verifySignatureAlgorithmManager,
        );

        $public_sig_JWK = new JWK($public_sig_jwk);

        // Extract `kid` from the token header
        $jwsHeader = json_decode(base64_decode(explode('.', $unencrypted_payload)[0]), true);
        $jws_kid = $jwsHeader['kid'];
        self::writeLog($jws_kid, 'JWS Header kid');

        // Retrieve Singpass's key using `kid`
        $singpass_key = self::getKeyForKid($jws_kid);
        self::writeLog($singpass_key, "Found kid");

        if ($jws) {
            if ($jwsVerifier->verifyWithKey($jws, $singpass_key, 0)) {
                $success_key = $singpass_key;
            } else {
                self::writeLog('unsuccess', 'jwsVerifier->$public_sig_JWK');
            }

            $jwsLoader = new JWSLoader(
                $signatureSerializerManager,
                $jwsVerifier,
                null,
            );

            self::writeLog($success_key);
            try {
                $jw_verified_response = $jwsLoader->loadAndVerifyWithKey(
                    $unencrypted_payload,
                    $success_key,
                    $signature,
                );
                $verified_payload = $jw_verified_response->getPayload();
                // print("\nAccess token: Successfully decrypted JWE & verified JWS: " . $verified_payload);

                $decoded_payload = json_decode($verified_payload, true);
                $expectedIssuer = self::base_url(get_option(self::SINGPASS_USERINFO_ENDPOINT));
                
                if ($decoded_payload['iss'] !== $expectedIssuer) {
                    self::writeLog('Userinfo validation failed: Invalid issuer', 'Userinfo Validation');
                    exit('Invalid issuer in Userinfo response');
                }

                $clientId = $_SESSION['client_id'] ?? '';
                
                if (is_array($decoded_payload['aud'])) {
                    if (!in_array($clientId, $decoded_payload['aud'])) {
                        self::writeLog('Userinfo validation failed: Invalid audience', 'Userinfo Validation');
                        exit('Invalid audience in Userinfo response (Arr)');
                    }
                } else {
                    if ($decoded_payload['aud'] !== $clientId) {
                        self::writeLog('Userinfo validation failed: Invalid audience', 'Userinfo Validation');
                        exit('Invalid audience in Userinfo response');
                    }
                }
                unset($_SESSION['client_id']);

                if ($decoded_payload['sub'] !== $validatedIdToken['sub']) {
                    self::writeLog('Userinfo validation failed: Subject mismatch', 'Userinfo Validation');
                    exit('Subject mismatch between Userinfo and ID Token');
                }

                self::writeLog($decoded_payload, 'Decoded Userinfo Payload');

                //alternative way rather than set_transient
                set_userinfo_data($verified_payload);

                // Redirect to the NinjaForm page
                wp_redirect(site_url('/singpass-testing-page?singpass=true')); // Replace with your form URL
                exit;
            } catch (Exception $e) {
                self::writeLog($e->getMessage());
                print ('nonserializable with public_sig_JWK');
            }
            // $headerbody = self::getHeaderPayloadFromIdToken($verified_payload);
            // return self::getNricUen($headerbody);
        }
    }

    function qr_code_scripts()
    {
        $appname = get_option(self::APP_NAME);
        $state = base64_encode($appname);
        $appslist = maybe_unserialize(get_option('mo_oauth_apps_list'));
        $clientId = $appslist[$appname]['clientid'];
        wp_enqueue_script('singpass_support_script', 'https://stg-id.singpass.gov.sg/static/ndi_embedded_auth.js');
        wp_enqueue_script('singpass_script', plugin_dir_url(__FILE__) . 'js/singpass.js');
        wp_localize_script('singpass_script', 'singpass_vars', array(
            'state' => $state,
            'redirectUri' => get_option(self::REDIRECT_URI),
            'clientId' => $clientId
        ));
        //        echo '<script src="https://stg-id.singpass.gov.sg/static/ndi_embedded_auth.js"></script>';
//        echo '<script src="' . $path . 'js/singpass.js"></script>';
    }

    public static function show_qr_code()
    {
        wp_enqueue_style('wp-pointer');
        wp_enqueue_script('wp-pointer');
        wp_enqueue_script('utils');
        ?>

        <body onload="init()">
            <div id="ndi-qr"></div>
        </body>
        <?php
    }


}

$mosingpassPlugin = new MosingpassPlugin();

?>