<?php
// $Id: DrupalOAuthServer.inc,v 1.1 2009/05/08 21:06:15 hugowetterberg Exp $

class DrupalOAuthServer extends OAuthServer {
  function __construct() {
    parent::__construct(new DrupalOAuthDataStore());
    $this->add_signature_method(new OAuthSignatureMethod_HMAC_SHA1());
    $this->add_signature_method(new OAuthSignatureMethod_RSA_SHA1());
    $this->add_signature_method(new OAuthSignatureMethod_PLAINTEXT());
  }
}
