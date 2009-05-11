<?php
// $Id$

class DrupalOAuthServer extends OAuthServer {
  function __construct() {
    parent::__construct(new DrupalOAuthDataStore());
    $this->add_signature_method(new OAuthSignatureMethod_HMAC_SHA1());
    $this->add_signature_method(new OAuthSignatureMethod_RSA_SHA1());
    $this->add_signature_method(new OAuthSignatureMethod_PLAINTEXT());
  }

  /**
   * Checks the body signature of the request.
   * Throws a exception if the body hash is invalid.
   *
   * @param OAuthRequest $req
   * @param string $body
   * @return bool
   *  Returns TRUE if the body was signed, FALSE if it wasn't.
   * @throws OAuthException
   *  Throws a exception if the body signature is invalid
   */
  public function verify_body_signature($req, $body='') {
    $oauth_body_hash = $req->get_parameter('oauth_body_hash');
    if ($oauth_body_hash) {
      $sha1 = base64_encode(sha1($body, TRUE));
      if ($sha1 !== $oauth_body_hash) {
        throw new OAuthException('The body signature was invalid');
      }
      return TRUE;
    }
    return FALSE;
  }
}
