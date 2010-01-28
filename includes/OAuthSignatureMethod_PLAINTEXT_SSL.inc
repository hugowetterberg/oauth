<?php

class OAuthSignatureMethod_PLAINTEXT_SSL extends OAuthSignatureMethod_PLAINTEXT {
  public function get_name() {
    return "PLAINTEXT_SSL";
  }

  public function build_signature($request, $consumer, $token) {
    if ($_SERVER['https'] == 'on') {
      $sig = array(
        OAuthUtil::urlencode_rfc3986($consumer->secret)
      );

      if ($token) {
        array_push($sig, OAuthUtil::urlencode_rfc3986($token->secret));
      } else {
        array_push($sig, '');
      }

      $raw = implode("&", $sig);
      // for debug purposes
      $request->base_string = $raw;

      return OAuthUtil::urlencode_rfc3986($raw);
    }
  }
}