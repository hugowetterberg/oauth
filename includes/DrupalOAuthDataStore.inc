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
    $result = db_query("SELECT * FROM {oauth_consumer}
      WHERE consumer_key = '%s'", $consumer_key);
    if ($object = db_fetch_object($result)) {
      return new OAuthConsumer($object->consumer_key, $object->consumer_secret);
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
    $result = db_query("SELECT * FROM {oauth_token}
      WHERE type = '%s' AND consumer_key = '%s' AND token_key = '%s'",
      $token_type, $consumer->key, $token);
    if ($object = db_fetch_object($result)) {
      return new OAuthToken($object->token_key, $object->token_secret);
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
   *   Strint. A new nonce value, in case a one doesnt current exit.
   * @param $timestamp
   *   Number. The current time.
   * @return
   *   String or NULL. The existing nonce value or NULL in
   *   case it doesnt exist.
   */
  function lookup_nonce($consumer, $token, $nonce, $timestamp) {
    if (!$nonce_1 = db_result(db_query("SELECT nonce FROM {oauth_nonce}
      WHERE timestamp <= %d and token = '%s'", $timestamp, $token))) {
      $sql = array(
        'nonce'     => $nonce,
        'timestamp' => $timestamp,
        'token'     => $token,
      );
      drupal_write_record('oauth_nonce', $sql);
      return NULL;
    }
    return $nonce_1;
  }

  /**
   * Generate a new request token.
   *
   * @param $consumer
   *   Object. The service consumer information.
   */
  function new_request_token($consumer) {
    $user_id = db_result(db_query("SELECT uid FROM {oauth_consumer}
      WHERE consumer_key = '%s'", $consumer->key));
    $token = new OAuthToken(user_password(32), user_password(32));
    $sql = array(
      'consumer_key'    => $consumer->key,
      'type'            => 'request',
      'token_key'       => $token->key,
      'token_secret'    => $token->secret,
      'uid'             => $user_id
    );
    drupal_write_record('oauth_token', $sql);
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
    if ($object = db_fetch_array(db_query("SELECT * FROM {oauth_token}
      WHERE type = 'request' AND token_key = '%s'", $token_old->key))) {
      if ($object['authorized']) {
        $token_new = new OAuthToken(user_password(32), user_password(32));
        $sql = array(
          'consumer_key'    => $consumer->key,
          'type'            => 'access',
          'token_key'       => $token_new->key,
          'token_secret'    => $token_new->secret,
          'uid'             => $object['uid']
        );
        drupal_write_record('oauth_token', $sql, array('uid', 'consumer_key'));

        return $token_new;
      }
    }
    throw new OAuthException('Invalid request token');
  }
}