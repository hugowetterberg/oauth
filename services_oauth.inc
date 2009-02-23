<?php
// $Id$

function _services_oauth_authorize() {
  // Check some important arguments
  if (empty($_GET['oauth_token'])) {
    drupal_set_message(t('Please include a valid OAuth token in your request.'), 'error');
    return drupal_access_denied();
  }
  elseif (empty($_GET['oauth_callback'])) {
    drupal_set_message(t('Please include a valid callback url in your request.'), 'error');
    return drupal_access_denied();
  }

  // Redirect to the right form, or present an error.
  global $user;
  if ($user->uid != 0) {
    if (!user_access('access services')) {
      drupal_set_message( t('You are not authorized to allow external services access to this system.'), 'error');
      return drupal_access_denied();
    }
    return drupal_get_form('_services_oauth_token_auth_form');
  }
  else {
    return drupal_get_form('user_login');
  }
}

/**
 * Form for granting access to the consumer
 *
 * Here user is asked to issue access/deny permission to
 * specific services as demanded by calling server
 *
 * @ingroup $form
 */
function _services_oauth_token_auth_form() {
  $req = OAuthRequest::from_request();

  $form['oauth_parameters'] = array(
    '#type'   => 'value',
    '#value'  => serialize($req->get_parameters()),
  );

  $form['confirm'] = array(
    '#type'   => 'submit',
    '#value'  => t('Grant access'),
  );
  return $form;
}

/**
 * Asks users for granting proper access/deny permissions for different services
 * Authorizes an existing oauth request token and redirects to sender.
 *
 * @ingroup form
 */
function _oauth_token_auth_form_submit(&$form, &$form_state) {
  // Unserialize the stored oauth parameters
  $parameters = unserialize($form_state['values']['oauth_parameters']);
  
  // Save the list of all services that the user allowed the
  // consumer to do
  global $user;
  $values = array(
    'authorized'  => 1,
    'uid'         => $user->uid,
    'token_key'   => $parameters['oauth_token'],
    'services'    => json_encode(array('*')),
  );
  drupal_write_record('services_oauth_token', $values, 'token_key');

  // Return to the consumer site
  drupal_goto($form_state['values']['oauth_callback']);
}

/**
 * Generate a request token from the request.
 *
 * @param $version
 *   The OAuth version used by the consumer: currently, its "1.0". Note
 *   that even its number, it will be treated as string.
 * @param $timestamp
 *   The time when the request was made (in timestamp).
 * @param $nonce
 *   A randon 32-char long string that ensure that a request is
 *   unique: even 2 requests from the same consumer must have different
 *   nonce values.
 * @param $consumer_key
 *   The consumer key, which is linked to a Drupal user.
 * @param $signature
 *   Using the signature method, its the resulting HASH value of all
 *   content. It uses the consumer keys and secrets, so its unique accross each
 *   request and consumer.
 */
function _services_oauth_token_request($version=NULL, $timestamp=NULL, $nonce=NULL, $consumer_key=NULL, $signature_method=NULL, $signature=NULL) {
  $server = new DrupalOauthServer();

  $arguments = NULL;
  // Only populate the arguments array if we got explicit arguments
  if ($version !== NULL) {
    $arguments = array(
      'oauth_token'             => $token_key,
      'oauth_consumer_key'      => $consumer_key,
      'oauth_version'           => $version,
      'oauth_timestamp'         => $timestamp,
      'oauth_nonce'             => $nonce,
      'oauth_signature_method'  => $signature_method,
      'oauth_signature'         => $signature,
    );
  }

  try {
    $req = OAuthRequest::from_request(NULL, NULL, $arguments);
    $token = $server->fetch_request_token($req);
    return $token;
  }
  catch (OAuthException $e) {
    drupal_set_header('HTTP/1.0 401 Unauthorized: ' . $e->getMessage());
    drupal_set_header(sprintf('WWW-Authenticate: OAuth realm="%s"', url('', array('absolute'=>TRUE))));
  }
}

/**
 * Access the OAuth services
 *
 * @param $version
 *   The OAuth version used by the consumer: currently, its "1.0". Note
 *   that even its number, it will be treated as string.
 * @param $timestamp
 *   Number. The time when the request was made (in timestamp).
 * @param $nonce
 *   A random 32-char long string that ensure that a request is
 *   unique: even 2 requests from the same consumer must have different
 *   nonce values.
 * @param $consumer_key
 *   The consumer key, which is linked to a Drupal user.
 * @param $token_key
 *   The request token, which will be replaced by the
 *   access token.
 * @param $signature
 *   Using the signature method, its the resulting HASH value of all
 *   content. It uses the consumer keys and secrets, so its unique accross each
 *   request and consumer.
 */
function _services_oauth_token_access($version=NULL, $timestamp=NULL, $nonce=NULL, $consumer_key=NULL, $token_key=NULL, $signature_method=NULL, $signature=NULL) {
  $server = new DrupalOauthServer();

  $arguments = NULL;
  // Only populate the arguments array if we got explicit arguments
  if ($version !== NULL) {
    $arguments = array(
      'oauth_token'             => $token_key,
      'oauth_consumer_key'      => $consumer_key,
      'oauth_version'           => $version,
      'oauth_timestamp'         => $timestamp,
      'oauth_nonce'             => $nonce,
      'oauth_signature_method'  => $signature_method,
      'oauth_signature'         => $signature,
    );
  }

  try {
    $req = OAuthRequest::from_request(NULL, NULL, $arguments);
    $token = $server->fetch_access_token($req);
    return $token;
  }
  catch (OAuthException $e) {
    drupal_set_header('HTTP/1.0 401 Unauthorized: ' . $e->getMessage());
    drupal_set_header(sprintf('WWW-Authenticate: OAuth realm="%s"', url('', array('absolute'=>TRUE))));
  }
}

/**
 * Return consumer object related to a user. If the consumer
 * does not exist, it will be created.
 *
 * @param $uid
 *   Number. User ID to retrieve consumer object for.
 * @return
 *   Object. OAuth service consumer.
 */
function _services_oauth_consumer_get($uid) {
  $result = db_query('SELECT * FROM {services_oauth_consumer} WHERE uid = %d', $uid);
  if ($object = db_fetch_array($result)) {
    return new OAuthConsumer($object['consumer_key'], $object['consumer_secret']);
  }
  else {
    $sql = array(
      'uid'             => $uid,
      'consumer_key'    => user_password(32),
      'consumer_secret' => user_password(32),
    );
    drupal_write_record('services_oauth_consumer', $sql);
    return new OAuthConsumer($sql['consumer_key'], $sql['consumer_secret']);
  }
}