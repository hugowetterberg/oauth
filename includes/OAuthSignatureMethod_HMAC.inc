<?php
// $Id$

class OAuthSignatureMethod_HMAC extends OAuthSignatureMethod {
  private $algo;
  
  public function __construct($algo) {
    $this->algo = $algo;
  }
  
  function get_name() {
    return "HMAC-" . strtoupper($this->algo);
  }

  public function build_signature($request, $consumer, $token) {
    $base_string = $request->get_signature_base_string();
    $request->base_string = $base_string;

    $key_parts = array(
      $consumer->secret,
      ($token) ? $token->secret : ""
    );

    $key_parts = OAuthUtil::urlencode_rfc3986($key_parts);
    $key = implode('&', $key_parts);

    return base64_encode(hash_hmac($this->algo, $base_string, $key, TRUE));
  }
}