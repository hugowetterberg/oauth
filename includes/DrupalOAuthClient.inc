<?php
// $Id$

class DrupalOAuthClient {
  public $version = OAUTH_COMMON_VERSION_1_RFC;

  protected $consumer;
  protected $requestToken;
  protected $accessToken;
  protected $signatureMethod;

  /**
   * Creates an instance of the DrupalOAuthClient.
   *
   * @param DrupalOAuthConsumer $consumer
   *  The consumer.
   * @param OAuthToken $request_token
   *  Optional. A request token to use.
   * @param OAuthSignatureMethod $signature_method
   *  Optional. The signature method to use.
   * @param integer $version
   *  Optional. The version to use - either OAUTH_COMMON_VERSION_1_RFC or OAUTH_COMMON_VERSION_1.
   */
  public function __construct($consumer, $request_token = NULL, $signature_method = NULL, $version = NULL) {
    $this->consumer = $consumer;
    $this->requestToken = $request_token;
    $this->signatureMethod = $signature_method;

    if ($version) {
      $this->version = $version;
    }

    // Set to the default signature method if no method was specified
    if (!$this->signatureMethod) {
      if (!empty($this->consumer->configuration['signature_method'])) {
        $signature_method = substr(strtolower($this->consumer->configuration['signature_method']), 5);
      }
      else {
        $signature_method = 'sha512';
      }
      $this->signatureMethod = self::signatureMethod($signature_method);
    }
  }

  /**
   * Convenience function to get signing method implementations.
   *
   * @param string $method
   *  Optional. The hmac hashing algorithm to use. Defaults to 'sha512' which
   *  has superseded sha1 as the recommended alternative.
   * @param bool $fallback_to_sha1
   *  Optional. Whether sha1 should be used as a fallback if the selected
   *  hashing algorithm is unavailable.
   * @return OAuthSignatureMethod
   *  The signature method object.
   */
  public static function signatureMethod($method = 'sha512', $fallback_to_sha1 = TRUE) {
    $sign = NULL;

    if (in_array($method, hash_algos())) {
      $sign = new OAuthSignatureMethod_HMAC($method);
    }
    else if ($fallback_to_sha1) {
      $sign = new OAuthSignatureMethod_HMAC('SHA1');
    }

    return $sign;
  }

  /**
   * Gets a request token from the provider.
   *
   * @param string $endpoint
   *  Optional. The endpoint path for the provider. Defaults to
   *  '/oauth/request_token'.
   * @param array $request_params
   *  Optional. A set of parameters to pass to the provider.
   * @param string $realm
   *  Optional. A http authentication realm to be used in the request.
   * @param boolean $get_method
   *  Optional. Whether to use GET as the HTTP-method instead of POST.
   * @return DrupalOAuthToken
   *  The returned request token.
   */
  public function getRequestToken($endpoint = '/oauth/request_token', $request_params = array(), $realm = NULL, $get_method = FALSE, $callback_url = NULL) {
    //TODO: Restructure this function - use an options array
    if (!$this->requestToken) {
      if ($this->version > OAUTH_COMMON_VERSION_1) {
        $request_params['oauth_callback'] = $callback_url ? $callback_url : 'oob';
      }
      $response = $this->get($endpoint, array(
          'params' => $request_params,
          'realm' => $realm,
          'get' => $get_method,
        ));
      $params = array();
      parse_str($response, $params);

      if (empty($params['oauth_token']) || empty($params['oauth_token_secret'])) {
        throw new Exception('No valid request token was returned');
      }

      if ($this->version > OAUTH_COMMON_VERSION_1 && empty($params['oauth_callback_confirmed'])) {
        $this->version = OAUTH_1;
      }

      $this->requestToken = new DrupalOAuthToken($params['oauth_token'], $params['oauth_token_secret'], array(
        'type' => 'request',
        'consumer_key' => $this->consumer->key,
        'provider_token' => FALSE,
        'version' => $this->version,
      ));
    }

    return clone $this->requestToken;
  }

  /**
   * Constructs the url that the user should be sent to to authorize the
   * request token.
   *
   * @param string $callback_url
   *  Optional. The url the user should be sent to after the request token has
   *  been authorized.
   * @param string $endpoint
   *  Optional. The endpoint path for the provider. Defaults to
   *  '/oauth/authorize'.
   * @param array $request_params
   *  Optional. Parameters to send to the provider.
   * @return string
   *  The url.
   */
  public function getAuthorizationUrl($callback_url = NULL, $endpoint = '/oauth/authorize', $request_params = array()) {
    $params = array_merge($request_params, array(
      'oauth_token' => $this->requestToken->key,
    ));
    if ($this->version == OAUTH_COMMON_VERSION_1 && $callback_url) {
      $params['oauth_callback'] = $callback_url;
    }
    //TODO: What if $endpoint has query parameters?
    return $this->getAbsolutePath($endpoint) . '?' . http_build_query($params, NULL, '&');
  }

  /**
   * Fetches the access token using the request token.
   *
   * @param string $endpoint
   *  Optional. The endpoint path for the provider. Defaults to
   *  the default access_endpoint for the $consumer.
   * @param string $request_params
   *  Optional. Parameters to send to the provider.
   * @param string $realm
   *  Optional. A http authentication realm to be used in the request.
   * @param boolean $get_method
   *  Optional. Whether to use GET as the HTTP-method instead of POST.
   * @param string $verifier
   *  Optional. A verifier returned by the provider if version is OAuth 1.0 RFC.
   * @return DrupalOAuthToken
   *  The access token.
   */
  public function getAccessToken($endpoint = NULL, $request_params = array(), $realm = NULL, $get_method = FALSE, $verifier = NULL) {
    if (!$this->accessToken) {
      if (empty($endpoint)) {
        if (!empty($this->consumer->configuration['access_endpoint'])) {
          $endpoint = $this->consumer->configuration['access_endpoint'];
        }
        else {
          $endpoint = '/oauth/access_token';
        }
      }
      if (empty($realm) && !empty($this->consumer->configuration['authentication_realm'])) {
        $realm = $this->consumer->configuration['authentication_realm'];
      }
      if ($this->version > OAUTH_COMMON_VERSION_1 && $verifier !== NULL) {
        $request_params['oauth_verifier'] = $verifier;
      }
      $response = $this->get($endpoint, array(
          'token' => TRUE,
          'params' => $request_params,
          'realm' => $realm,
          'get' => $get_method,
        ));
      $params = array();
      parse_str($response, $params);

      if (empty($params['oauth_token']) || empty($params['oauth_token_secret'])) {
        throw new Exception('No valid access token was returned');
      }

      // Check if we've has recieved this token previously and if so use the old one
      $this->accessToken = DrupalOAuthToken::load($params['oauth_token'], FALSE);
      //TODO: Can a secret change even though the token doesn't? If so it needs to be changed.
      if (!$this->accessToken) {
        $this->accessToken = new DrupalOAuthToken($params['oauth_token'], $params['oauth_token_secret'], array(
          'type' => 'access',
          'consumer_key' => $this->consumer->key,
          'provider_token' => FALSE,
        ));
      }
    }

    return clone $this->accessToken;
  }

  /**
   * Make an OAuth request.
   *
   * @param string $path
   *   The path being requested.
   *     - If you provide the full URL (e.g. "http://example.com/oauth/request_token"),
   *       then it will be used.
   *     - If you provide only the path (e.g. "oauth/request_token"), it will
   *       be converted into a full URL by prepending the provider_url.
   * @param array $options
   *   An associative array of additional options, with the following keys:
   *     - 'token' (default FALSE)
   *       Whether a token should be used or not.
   *     - 'params'
   *       An associative array of parameters that should be included in the
   *       request.
   *     - 'realm'
   *       A string to be used as the authentication realm.
   *     - 'get' (default FALSE)
   *       Whether the request should be a GET request instead of a POST.
   * @return string
   *   a string containing the response body.
   */
  protected function get($path, $options = array()) {
    $options += array(
        'token' => FALSE,
        'params' => array(),
        'realm' => NULL,
        'get' => FALSE,
      );

    $token = $options['token'] ? $this->requestToken : NULL;
    $path = $this->getAbsolutePath($path);

    $req = OAuthRequest::from_consumer_and_token($this->consumer, $token,
      $options['get'] ? 'GET' : 'POST', $path, $options['params']);
    $req->sign_request($this->signatureMethod, $this->consumer, $token);

    $url = $req->get_normalized_http_url();
    $params = array();
    foreach ($req->get_parameters() as $param_key => $param_value) {
      if (substr($param_key, 0, 5) != 'oauth') {
        $params[$param_key] = $param_value;
      }
    }
    if (!empty($params)) {
      $url .= '?' . http_build_query($params);
    }

    $headers = array(
      'Accept: application/x-www-form-urlencoded',
      $req->to_header($options['realm']),
    );

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    if (!$options['get']) {
      curl_setopt($ch, CURLOPT_POST, 1);
      curl_setopt($ch, CURLOPT_POSTFIELDS, '');
    }
    $oauth_version = _oauth_common_version();
    curl_setopt($ch, CURLOPT_USERAGENT, 'Drupal/' . VERSION . ' OAuth/' . $oauth_version);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_HEADER, 1);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

    $response = curl_exec($ch);
    $error = curl_error($ch);
    curl_close($ch);

    if ($error) {
      throw new Exception($error);
    }

    $result = $this->interpretResponse($response);
    if ($result->responseCode != 200) {
      throw new Exception('Failed to fetch data from url "' . $path . '" (HTTP response code ' . $result->responseCode . ' ' . $result->responseMessage . '): ' . $result->body, $result->responseCode);
    }

    return $result->body;
  }

  /**
   * Makes sure a path is an absolute path
   *
   * Prepends provider url if the path isn't absolute.
   *
   * @param string $path
   *  The path to make absolute.
   * @return string
   *  The absolute path.
   */
  protected function getAbsolutePath($path) {
    $protocols = array(
      'http',
      'https'
    );
    $protocol = strpos($path, '://');
    $protocol = $protocol ? substr($path, 0, $protocol) : '';
    if (!in_array($protocol, $protocols)) {
      $path = $this->consumer->configuration['provider_url'] . $path;
    }
    return $path;
  }

  protected function interpretResponse($res) {
    list($headers, $body) = preg_split('/\r\n\r\n/', $res, 2);

    $obj = (object)array(
      'headers' => $headers,
      'body' => $body,
    );

    $matches = array();
    if (preg_match('/HTTP\/1.\d (\d{3}) (.*)/', $headers, $matches)) {
      $obj->responseCode = trim($matches[1]);
      $obj->responseMessage = trim($matches[2]);

      // Handle HTTP/1.1 100 Continue
      if ($obj->responseCode == 100) {
        return $this->interpretResponse($body);
      }
    }

    return $obj;
  }
}
