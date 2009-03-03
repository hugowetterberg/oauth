<?php
// $Id$

function _oauth_common_validate_request_callback($type) {
  try {
    module_load_include('inc', 'oauth_common');

    list($consumer, $token) = oauth_common_verify_request();

    if ($consumer==NULL) {
      throw new OAuthException('Missing consumer token');
    }

    if ($token==NULL && $type=='access token') {
      throw new OAuthException('Missing access token');
    }
  }
  catch (OAuthException $e) {
    drupal_set_header('HTTP/1.0 401 Unauthorized: ' . $e->getMessage());
    drupal_set_header(sprintf('WWW-Authenticate: OAuth realm="%s"', url('', array('absolute'=>TRUE))));
  }
  exit;
}