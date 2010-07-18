<?php
// $Id$

class DrupalOAuthServer extends OAuthServer {
  private $context;

  public function __construct($context) {
    $this->context = $context;
    parent::__construct(new DrupalOAuthDataStore($context));
  }

  /**
   * Figure out the signature method using context configuration.
   */
  protected function get_signature_method($request) {
    $signature_method = $request instanceof OAuthRequest
        ? $request->get_parameter("oauth_signature_method")
        : NULL;

    if (!$signature_method) {
      // According to chapter 7 ("Accessing Protected Ressources") the signature-method
      // parameter is required, and we can't just fallback to PLAINTEXT
      throw new OAuthException('No signature method parameter. This parameter is required');
    }

    // Check what signature methods we should support.
    $sig_methods = isset($this->context->authorization_options['signature_methods']) ?
      $this->context->authorization_options['signature_methods'] :
      array('HMAC-SHA1', 'HMAC-SHA256', 'HMAC-SHA384', 'HMAC-SHA512');

    // Get the signature method implementation if supported.
    $impl = NULL;
    if (in_array($signature_method, $sig_methods)) {
      if ($signature_method === 'PLAINTEXT') {
        $impl = new OAuthSignatureMethod_PLAINTEXT();
      }
      else if (substr($signature_method, 0, 5) == 'HMAC-') {
        $algo = substr(strtolower($signature_method), 5);
        // Check if the system supports the hashing algorithm
        if (in_array($algo, hash_algos())) {
          $impl = new OAuthSignatureMethod_HMAC($algo);
        }
      }
    }

    if (!$impl) {
      throw new OAuthException(
        "Signature method '$signature_method' not supported " .
        "try one of the following: " .
        implode(", ", $sig_methods)
      );
    }

    return $impl;
  }
}
