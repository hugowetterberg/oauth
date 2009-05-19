<?php
// $Id: DrupalOAuthServer.inc,v 1.1 2009/05/08 21:06:15 hugowetterberg Exp $

class DrupalOAuthServer extends OAuthServer {
  function __construct() {
    parent::__construct(new DrupalOAuthDataStore());
    $this->add_signature_method(new OAuthSignatureMethod_HMAC_SHA1());
    $this->add_signature_method(new OAuthSignatureMethod_PLAINTEXT());

    $hmac = array_intersect(variable_get('oauth_common_hmac_supported',
        array('sha256', 'sha384', 'sha512', 'crc32')),
      hash_algos());
    foreach ($hmac as $algo) {
      $this->add_signature_method(new OAuthSignatureMethod_HMAC($algo));
    }
  }
}
