<?php
// $Id: DrupalOAuthServer.inc,v 1.3 2010/01/19 10:43:58 hugowetterberg Exp $

class DrupalOAuthServer extends OAuthServer {
  private $context;

  public function __construct($context) {
    $this->context = $context;
    parent::__construct(new DrupalOAuthDataStore($context));
  }

  /**
   * Overriding the verify_request method to inject the signature method on
   * demand instead of creating instances of all available methods as done before.
   *
   * @param OAuthRequest $req
   *  The request object.
   * @return void
   */
  public function verify_request($req) {
    // Load consumer and context.
    $sig_method = $req->get_parameter('oauth_signature_method');

    // Check what signature methods we should support.
    $sig_methods = isset($context->authorization_options['signature_methods']) ?
      $this->context->authorization_options['signature_methods'] :
      array('PLAINTEXT-SSL', 'HMAC-SHA1', 'HMAC-SHA256', 'HMAC-SHA384', 'HMAC-SHA512', 'HMAC-CRC32');

    // Get the signature method implementation if supported.
    $impl = NULL;
    if (in_array($sig_method, $sig_methods)) {
      if ($sig_method === 'PLAINTEXT') {
        $impl = new OAuthSignatureMethod_PLAINTEXT();
      }
      else if (substr($sig_method, 0, 5) == 'HMAC-') {
        $algo = substr(strtolower($sig_method), 5);
        // Check if the system supports the hashing algorithm
        if (in_array($algo, hash_algos())) {
          $impl = new OAuthSignatureMethod_HMAC($algo);
        }
      }
    }

    // Add the signature method to the signature_methods array if it
    // was supported.
    if ($impl) {
      $this->signature_methods = array($impl->get_name() => $impl);
    }
    else {
      $this->signature_methods = array();
    }

    // Pass on to OAuthServer::verify_request().
    return parent::verify_request($req);
  }
}
