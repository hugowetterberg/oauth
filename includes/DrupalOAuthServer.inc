<?php
// $Id$

class DrupalOAuthServer extends OAuthServer {
  function __construct() {
    parent::__construct(new DrupalOAuthDataStore());
    $this->add_signature_method(new OAuthSignatureMethod_HMAC_SHA1());
    $this->add_signature_method(new OAuthSignatureMethod_RSA_SHA1());
  }
}
