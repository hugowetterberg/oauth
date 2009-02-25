<?php
// $Id$

function services_oauth_services_authenticate_call($method, $args, $data) {
  if (!isset($method['#key']) || !$method['#key']) {
    return FALSE;
  }

  try {
    list($consumer, $token) = services_oauth_verify_request();
    services_oauth_set_user($token);
  }
  catch (OAuthException $e) {
    drupal_set_header('HTTP/1.0 401 Unauthorized: ' . $e->getMessage());
    drupal_set_header(sprintf('WWW-Authenticate: OAuth realm="%s"', url('', array('absolute'=>TRUE))));
    return $e->getMessage();
  }
}

function services_oauth_services_security_settings() {
  return array();
}

function services_oauth_services_security_settings_submit() {
}