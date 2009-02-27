<?php
// $Id$

function services_oauth_services_authenticate_call($method, $args) {
  if (!isset($method['#key']) || !$method['#key']) {
    return FALSE;
  }

  try {
    list($consumer, $token) = services_oauth_verify_request();

    if ($consumer==NULL) {
      throw new OAuthException('Missing consumer token');
    }

    if ($token==NULL && $method['#delegate-key']) {
      throw new OAuthException('Missing access token');
    }

    services_oauth_set_user($token);
  }
  catch (OAuthException $e) {
    drupal_set_header(sprintf('WWW-Authenticate: OAuth realm="%s"', url('', array('absolute'=>TRUE))));
    return $e->getMessage();
  }
}

function services_oauth_services_security_settings() {
  return array();
}

function services_oauth_services_security_settings_submit() {
}

function services_oauth_services_alter_methods(&$methods) {
}