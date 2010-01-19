<?php
// $Id$

class DrupalOAuthClient {
  private $server;
  private $consumer;
  private $requestToken;
  private $accessToken;

  function __construct($server, $consumer, $requestToken = NULL) {
    $this->server = $server;
    $this->consumer = $consumer;
    $this->requestToken = $requestToken;
  }

  public static function signatureMethod($method = NULL) {
    static $sign;
    if (!$sign) {
      if ((empty($method) || $method == 'sha512') && in_array('sha512', hash_algos())) {
        $sign = new OAuthSignatureMethod_HMAC('sha512');
      }
      else {
        $sign = new OAuthSignatureMethod_HMAC_SHA1();
      }
    }
    return $sign;
  }

  public function getRequestToken($path = NULL, $request_params = array()) {
    if (!$this->requestToken) {
      $path = (empty($path) ? '/oauth/request_token' : $path);
      $response = $this->get($path, FALSE, $request_params);
      $params = array();
      parse_str($response, $params);

      if (empty($params['oauth_token']) || empty($params['oauth_token_secret'])) {
        throw new Exception('No valid request token was returned');
      }

      $this->requestToken = new OAuthToken($params['oauth_token'], $params['oauth_token_secret']);
    }

    return clone $this->requestToken;
  }

  public function getAuthorizationUrl($callback_url = NULL, $path = NULL, $request_params = array()) {
    $path = (empty($path) ? '/oauth/authorize' : $path);
    $params = array(
      'oauth_token' => $this->requestToken->key,
    );
    if ($callback_url) {
      $params['oauth_callback'] = $callback_url;
    }
    $params = array_merge($params, $request_params);
    return $this->server . $path . '?' . http_build_query($params, NULL, '&');
  }

  public function getAccessToken($path = NULL, $request_params = array()) {
    if (!$this->accessToken) {
      $path = (empty($path) ? '/oauth/access_token' : $path);
      $response = $this->get($path, TRUE, $request_params);
      $params = array();
      parse_str($response, $params);

      if (empty($params['oauth_token']) || empty($params['oauth_token_secret'])) {
        throw new Exception('No valid access token was returned');
      }

      $this->accessToken = new OAuthToken($params['oauth_token'], $params['oauth_token_secret']);
    }

    return clone $this->accessToken;
  }

  public function get($path, $use_token = FALSE, $params = array()) {
    $token = $use_token ? $this->requestToken : NULL;
    $req = OAuthRequest::from_consumer_and_token($this->consumer, $token,
      "GET", $this->server . $path, $params);
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
      throw new Exception('Failed to fetch data from url "'. $this->server . $path . '" (HTTP response code ' . $result->responseCode . '): ' . $result->responseMessage, $result->responseCode);
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
