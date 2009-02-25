<?php
// $Id$

/**
* Database abstraction class
*/
class DrupalOAuthDataStore extends OAuthDataStore {
  /**
   * Check if consumer exists from a given consumer key.
   *
   * @param $consumer_key
   *   String. The consumer key.
   */
  function lookup_consumer($consumer_key) {
    $consumer_secret = db_result(db_query("SELECT consumer_secret FROM {services_oauth_consumer}
      WHERE consumer_key = '%s'", array(
        ':consumer_key' => $consumer_key,
      )));
    if ($consumer_secret) {
      return new OAuthConsumer($consumer_key, $consumer_secret);
    }
    throw new OAuthException('Consumer not found');
  }

  /**
   * Check if the token exists.
   *
   * @param $consumer
   *   Object. The service consumer information.
   * @param $token_type
   *   Strint. The type of the token: 'request' or 'access'.
   * @param $token
   *   Strint. The token value.
   * @return
   *   String or NULL. The existing token or NULL in
   *   case it doesnt exist.
   */
  function lookup_token($consumer, $token_type, $token) {
    $token_secret = db_result(db_query("SELECT token_secret
      FROM {services_oauth_token}
      WHERE type = '%s' AND consumer_key = '%s' AND token_key = '%s'", array(
        ':type' => $token_type,
        ':consumer_key' => $consumer->key,
        ':token_key' => $token,
      )));
    if ($token_secret) {
      return new OAuthToken($token, $token_secret);
    }
    throw new OAuthException('Token not found');
  }

  /**
   * Check if the nonce value exists. If not, generate one.
   *
   * @param $consumer
   *   Object. The service consumer information with both key
   *   and secret values.
   * @param $token
   *   Strint. The current token.
   * @param $nonce
   *   Strint. A new nonce value, in case a one doesn't current exit.
   * @param $timestamp
   *   Number. The current time.
   * @return
   *   String or NULL. The existing nonce value or NULL in
   *   case it doesn't exist.
   */
  function lookup_nonce($consumer, $token, $nonce, $timestamp) {
    $stored_nonce = db_result(db_query(
      "SELECT nonce FROM {services_oauth_nonce}
      WHERE nonce='%s' AND timestamp <= %d and token = '%s'", array(
        ':nonce' => $nonce,
        ':timestamp' => $timestamp,
        ':token' => $token->key,
      )));

    if (!$stored_nonce) {
      $values = array(
        'nonce'     => $nonce,
        'timestamp' => $timestamp,
        'token'     => $token->key,
      );
      drupal_write_record('services_oauth_nonce', $values);
      return NULL;
    }

    return $stored_nonce;
  }

  /**
   * Generate a new request token.
   *
   * @param $consumer
   *   Object. The service consumer information.
   */
  function new_request_token($consumer) {
    $token = new OAuthToken(user_password(32), user_password(32));
    $values = array(
      'consumer_key'    => $consumer->key,
      'type'            => 'request',
      'token_key'       => $token->key,
      'token_secret'    => $token->secret,
      'uid'             => 0,
    );
    drupal_write_record('services_oauth_token', $values);
    return $token;
  }

  /**
   * Generate a new access token and delete the old request token.
   *
   * @param $token_old
   *   Strint. The old request token.
   * @param $consumer
   *   Object. The service consumer information.
   */
  function new_access_token($token_old, $consumer) {
    module_load_include('inc', 'services_oauth');
    $obj = services_oauth_get_token($token_old->key);

    if ($obj && $obj->authorized) {
      $token_new = new OAuthToken(user_password(32), user_password(32));
      db_query("DELETE FROM {services_oauth_token} WHERE token_key='%s'", array(
        ':token_key' => $token_old->key,
      ));

      $values = array(
        'token_key'       => $token_new->key,
        'token_secret'    => $token_new->secret,
        'type'            => 'access',
        'uid'             => $obj->uid,
        'consumer_key'    => $consumer->key,
        'services'        => $obj->services,
        'authorized'      => 1,
      );
      drupal_write_record('services_oauth_token', $values);
      return $token_new;
    }
    throw new OAuthException('Invalid request token');
  }
}