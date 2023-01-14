<?php

class MOOAuth_Custom_OAuth1{

    public static function mo_oauth1_auth_request($appname)
    {	
        $appslist = maybe_unserialize(get_option('mo_oauth_apps_list'));

        $client_id = $appslist[$appname]['clientid'];
        $client_secret = $appslist[$appname]['clientsecret'];

        $authorize_url = $appslist[$appname]['authorizeurl'];
        $request_token_url = $appslist[$appname]['requesturl'];
        $access_token_url = $appslist[$appname]['accesstokenurl'];
        $userinfo_url = $appslist[$appname]['resourceownerdetailsurl'];
        
        $oauth1_getrequest_object = new MOOAuth_Custom_OAuth1_Flow($client_id, $client_secret, $request_token_url, $access_token_url, $userinfo_url); 
        $request_token = $oauth1_getrequest_object->mo_oauth1_get_request_token();
        if(strpos($authorize_url, '?') == false){
            $authorize_url .= '?';
        }        
        $login_dialog_url = $authorize_url . 'oauth_token='.$request_token;
        if($request_token == '' || $request_token == NULL){
            
            wp_die('Invalid token received. Contact to your admimistrator for more information.');
        }
        header('Location:'. $login_dialog_url);
        exit;
    }

    static function mo_oidc1_get_access_token($appname)
    {
        $dirs = explode('&', sanitize_text_field($_SERVER['REQUEST_URI']));
        $oauth_verifier = explode('=', $dirs[1]);
        $mo_oauth1_oauth_token = explode('=', $dirs[0]);

        $appslist = get_option('mo_oauth_apps_list');
        $currentappname = $appname;
        $currentapp = null;
        foreach($appslist as $key => $app){
	        if($appname == $key){
	            $currentapp = $app;
	            break;
	        }
        }

        $appslist = maybe_unserialize(get_option('mo_oauth_apps_list'));
        $client_id = $appslist[$appname]['clientid'];
        $client_secret = $appslist[$appname]['clientsecret'];
        $request_token_url = $appslist[$appname]['requesturl'];
        $access_token_url = $appslist[$appname]['accesstokenurl'];
        $userinfo_url = $appslist[$appname]['resourceownerdetailsurl'];
        
        $mo_oauth1_getaccesstoken_object = new MOOAuth_Custom_OAuth1_Flow($client_id,$client_secret,$request_token_url,$access_token_url,$userinfo_url);
        $oauth_token = $mo_oauth1_getaccesstoken_object->mo_oauth1_get_access_token($oauth_verifier[1],$mo_oauth1_oauth_token[1]);

        $response_parse = explode('&', $oauth_token);
        
        $oa_token = '';
        $oa_secret = '';

        foreach ($response_parse as $key) {
        	$arg_parse = explode('=', $key);
        	if($arg_parse[0] == 'oauth_token'){
        		$oa_token = $arg_parse[1];
        	}
        	elseif($arg_parse[0] == 'oauth_token_secret'){
        		$oa_secret = $arg_parse[1];
        	}
        }
    
        $mo_oauth1_get_profile_signature_object = new MOOAuth_Custom_OAuth1_Flow($client_id,$client_secret,$request_token_url,$access_token_url,$userinfo_url);
        $oauth_access_token1 =     isset($oauth_access_token[1]) ? $oauth_access_token[1] : '';
        $oauth_token_secret1 =    isset($oauth_token_secret[1]) ? $oauth_token_secret[1] : '';
        $screen_name1    =   isset($screen_name[1]) ? $screen_name[1] : '';

        $profile_json_output = $mo_oauth1_get_profile_signature_object->mo_oauth1_get_profile_signature($oa_token,$oa_secret);
        if(!isset($profile_json_output)){
            wp_die('Invalid Configurations. Please contact to the admimistrator for more information');
        }
        return $profile_json_output;
    }

}

class MOOAuth_Custom_OAuth1_Flow{

    var $key = '';
    var $secret = '';

    var $request_token_url = '';
    var $access_token_url  = '';
    var $userinfo_url      = '';

    function __construct($client_key,$client_secret, $request_token_url, $access_token_url, $userinfo_url)
    {
        $this->key = $client_key; // consumer key 
        $this->secret = $client_secret; // secret 
        $this->request_token_url = $request_token_url;
        $this->access_token_url = $access_token_url;
        $this->userinfo_url = $userinfo_url;
    }

    function mo_oauth1_get_request_token()
    {
        // Default params
        $params = array(
            "oauth_version" => "1.0",
            "oauth_nonce" => time(),
            "oauth_timestamp" => time(),
            "oauth_consumer_key" => $this->key,
            "oauth_signature_method" => "HMAC-SHA1",
            //"oauth_callback" => "http://localhost/wordpress5"
        );

        if(strpos($this->request_token_url,'?')!=false){
        		$temp = explode('?', $this->request_token_url);
        		$this->request_token_url = $temp[0];
        		$param = explode('&', $temp[1]);
        		foreach ($param as $arr) {
        			$pair = explode('=', $arr);
        			$params[$pair[0]] = $pair[1];
        		}
        }	
        // BUILD SIGNATURE
        // encode params keys, values, join and then sort.
        $keys = $this->mo_oauth1_url_encode_rfc3986(array_keys($params));
        $values = $this->mo_oauth1_url_encode_rfc3986(array_values($params));
        $params = array_combine($keys, $values);
        uksort($params, 'strcmp');
       
        foreach ($params as $k => $v) {
            $pairs[] = $this->mo_oauth1_url_encode_rfc3986($k).'='.$this->mo_oauth1_url_encode_rfc3986($v);
        }
        $concatenatedParams = implode('&', $pairs);
        
        $baseString= ($concatenatedParams);
        // form secret (second key)
        $baseString = str_replace('=', '%3D', $baseString);
        $baseString = str_replace('&', '%26', $baseString);
        $baseString = 'GET&'.$this->mo_oauth1_url_encode_rfc3986($this->request_token_url)."&".$baseString;

        $secret = $this->mo_oauth1_url_encode_rfc3986($this->secret)."&";
        // make signature and append to params
        $params['oauth_signature'] = $this->mo_oauth1_url_encode_rfc3986(base64_encode(hash_hmac('sha1', $baseString, $secret, TRUE)));

        // BUILD URL
        // Resort
        uksort($params, 'strcmp');
        // convert params to string
        foreach ($params as $k => $v) {$urlPairs[] = $k."=".$v;}
        $concatenatedUrlParams = implode('&', $urlPairs);
        // form url
        $url = $this->request_token_url."?".$concatenatedUrlParams;
        // Send to cURL
        $response = $this->mo_oauth1_https($url);
       
        $respone_parse = explode('&', $response);

        $oauth_token_ret = '';

        foreach ($respone_parse as $key) {
        	$arg_parse = explode('=', $key);
        	if($arg_parse[0] == 'oauth_token'){
        		$oauth_token_ret = $arg_parse[1];
        	}
        	elseif($arg_parse[0] == 'oauth_token_secret'){
        		setcookie('mo_ts', $arg_parse[1], time()+30);
        	}
        }

        return $oauth_token_ret;
    }

    function mo_oauth1_get_access_token($oauth_verifier, $mo_oauth1_oauth_token)
    {
        $params = array(
            "oauth_version" => "1.0",
            "oauth_nonce" => time(),
            "oauth_timestamp" => time(),
            "oauth_consumer_key" => $this->key,
            "oauth_token" => $mo_oauth1_oauth_token,
            "oauth_signature_method" => "HMAC-SHA1",
            "oauth_verifier" => $oauth_verifier
        );

        $keys = $this->mo_oauth1_url_encode_rfc3986(array_keys($params));
        $values = $this->mo_oauth1_url_encode_rfc3986(array_values($params));
        $params = array_combine($keys, $values);
        uksort($params, 'strcmp');

        foreach ($params as $k => $v) {
            $pairs[] = $this->mo_oauth1_url_encode_rfc3986($k).'='.$this->mo_oauth1_url_encode_rfc3986($v);
        }
        $concatenatedParams = implode('&', $pairs);

        $baseString= ($concatenatedParams);
        // form secret (second key)
        $baseString = str_replace('=', '%3D', $baseString);
        $baseString = str_replace('&', '%26', $baseString);

        $baseString = 'GET&'.$this->mo_oauth1_url_encode_rfc3986($this->access_token_url)."&".$baseString;
        
        $mo_ts = isset($_COOKIE['mo_ts'])?sanitize_text_field($_COOKIE['mo_ts']):'';
        $secret = $this->mo_oauth1_url_encode_rfc3986($this->secret).'&'.$mo_ts;
        $params['oauth_signature'] = $this->mo_oauth1_url_encode_rfc3986(base64_encode(hash_hmac('sha1', $baseString, $secret, TRUE)));

        uksort($params, 'strcmp');
        foreach ($params as $k => $v) {$urlPairs[] = $k."=".$v;}
        $concatenatedUrlParams = implode('&', $urlPairs);
        $url = $this->access_token_url."?".$concatenatedUrlParams;
       
        $response = $this->mo_oauth1_https($url);
        return $response;
    }

    function mo_oauth1_get_profile_signature($oauth_token, $oauth_token_secret, $screen_name='')
    {
        $params = array(
            "oauth_version" => "1.0",
            "oauth_nonce" => time(),
            "oauth_timestamp" => time(),
            "oauth_consumer_key" => $this->key,
            "oauth_token" => $oauth_token,
            "oauth_signature_method" => "HMAC-SHA1",
        );

        if(strpos($this->userinfo_url,'?')!=false){
        		$temp = explode('?', $this->userinfo_url);
        		$this->userinfo_url = $temp[0];
        		$param = explode('&', $temp[1]);
        		foreach ($param as $arr) {
        			$pair = explode('=', $arr);
        			$params[$pair[0]] = $pair[1];
        		}
        }	
  
        $keys = $this->mo_oauth1_url_encode_rfc3986(array_keys($params));
        $values = $this->mo_oauth1_url_encode_rfc3986(array_values($params));
        $params = array_combine($keys, $values);
        uksort($params, 'strcmp');

        foreach ($params as $k => $v) {
            $pairs[] = $this->mo_oauth1_url_encode_rfc3986($k).'='.$this->mo_oauth1_url_encode_rfc3986($v);
        }
        $concatenatedParams = implode('&', $pairs);

        $baseString= "GET&".$this->mo_oauth1_url_encode_rfc3986($this->userinfo_url)."&".$this->mo_oauth1_url_encode_rfc3986($concatenatedParams);

        $secret = $this->mo_oauth1_url_encode_rfc3986($this->secret)."&". $this->mo_oauth1_url_encode_rfc3986($oauth_token_secret);
        $params['oauth_signature'] = $this->mo_oauth1_url_encode_rfc3986(base64_encode(hash_hmac('sha1', $baseString, $secret, TRUE)));

        uksort($params, 'strcmp');
        foreach ($params as $k => $v) {$urlPairs[] = $k."=".$v;}
        $concatenatedUrlParams = implode('&', $urlPairs);
        $url = $this->userinfo_url.'?'.$concatenatedUrlParams;
       
        $args = array();

        $get_response = wp_remote_get($url,$args);
        $profile_json_output = json_decode($get_response['body'], true);

        return  $profile_json_output;
    }

    function mo_oauth1_https($url, $post_data = null){
    	if(isset($post_data))
        {
            $args = array(
                'method' => 'POST',
                'body' => $post_data,
                'timeout' => '5',
                'redirection' => '5',
                'httpversion' => '1.0',
                 'blocking' => true
            );
           
            $post_response = wp_remote_post($url,$args);
            return $post_response['body'];
        }
        $args = array();

        $get_response = wp_remote_get($url,$args);
            
        if ( is_wp_error( $get_response ) ) {
            MOOAuth_Debug::mo_oauth_log('Invalid response recieved. Please contact your administrator for more information.');
            MOOAuth_Debug::mo_oauth_log($get_response);
            wp_die( esc_html($response) );
        }
            
        $response =  $get_response['body'];
        return $response;
    }

    function mo_oauth1_url_encode_rfc3986($input)
    {
        if (is_array($input)) {
            return array_map(array('MOOAuth_Custom_OAuth1_Flow', 'mo_oauth1_url_encode_rfc3986'), $input);
        }
        elseif (is_scalar($input)) {
            return str_replace('+',' ',str_replace('%7E', '~', rawurlencode($input)));
        }
        else{
            return '';
        }
    }
}