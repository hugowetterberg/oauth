<?php
// $Id: DrupalOAuthClient.inc,v 1.6 2010/02/20 22:37:03 hugowetterberg Exp $

class DrupalOAuthClient {
  private $consumer;
  private $requestToken;
  private $accessToken;
  private $signatureMethod;

  /**
   * Creates an instance of the DrupalOAuthClient.
   *
   * @param DrupalOAuthConsumer $consumer
   *  The consumer.
   * @param OAuthToken $request_token
   *  Optional. A request token to use.
   * @param OAuthSignatureMethod $signature_method
   *  Optional. The signature method to use.
   */
  public function __construct($consumer, $request_token = NULL, $signature_method = NULL) {
    $this->consumer = $consumer;
    $this->requestToken = $request_token;
    $this->signatureMethod = $signature_method;

    // Set to the default signature method if no method was specified
    if (!$this->signatureMethod) {
      $this->signatureMethod = self::signatureMethod();
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
      $sign = new OAuthSignatureMethod_HMAC_SHA1();
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
   * @return DrupalOAuthToken
   *  The returned request token.
   */
  public function getRequestToken($endpoint = '/oauth/request_token', $request_params = array()) {
    if (!$this->requestToken) {
      $response = $this->get($endpoint, FALSE, $request_params);
      $params = array();
      parse_str($response, $params);

      if (empty($params['oauth_token']) || empty($params['oauth_token_secret'])) {
        throw new Exception('No valid request token was returned');
      }

      $this->requestToken = new DrupalOAuthToken($params['oauth_token'], $params['oauth_token_secret'], array(
        'type' => 'request',
        'consumer_key' => $this->consumer->key,
        'provider_token' => FALSE,
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
    if ($callback_url) {
      $params['oauth_callback'] = $callback_url;
    }
    return $this->consumer->configuration['provider_url'] . $endpoint . '?' . http_build_query($params, NULL, '&');
  }

  /**
   * Fetches the access token using the request token.
   *
   * @param string $endpoint
   *  Optional. The endpoint path for the provider. Defaults to
   *  the default access_endpoint for the $consumer.
   * @param string $request_params
   *  Optional. Parameters to send to the provider.
   * @return DrupalOAuthToken
   *  The access token.
   */
  public function getAccessToken($endpoint = NULL, $request_params = array()) {
    if (!$this->accessToken) {
      if (empty($endpoint) && !empty($this->consumer->configuration['access_endpoint'])) {
        $this->consumer->configuration['access_endpoint'];
      }
      if (empty($endpoint)) {
        $endpoint = '/oauth/access_token';
      }
      $response = $this->get($endpoint, TRUE, $request_params);
      $params = array();
      parse_str($response, $params);

      if (empty($params['oauth_token']) || empty($params['oauth_token_secret'])) {
        throw new Exception('No valid access token was returned');
      }

      $this->accessToken = new DrupalOAuthToken($params['oauth_token'], $params['oauth_token_secret'], array(
        'type' => 'access',
        'consumer_key' => $this->consumer->key,
        'provider_token' => FALSE,
      ));
    }

    return clone $this->accessToken;
  }

  private function get($path, $use_token = FALSE, $params = array()) {
    $token = $use_token ? $this->requestToken : NULL;
    $conf = $this->consumer->configuration;
    $req = OAuthRequest::from_consumer_and_token($this->consumer, $token,
      "GET", $conf['provider_url'] . $path, $params);
    $req->sign_request(self::signatureMethod(), $this->consumer, $token);

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $req->to_url());
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
      throw new Exception('Failed to fetch data from url "' . $conf['provider_url'] . $path . '" (HTTP response code ' . $result->responseCode . '): ' . $result->responseMessage, $result->responseCode);
    }

    return $result->body;
  }

  private function interpretResponse($res) {
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
