<?php
// $Id: DrupalOAuthDataStore.inc,v 1.2 2009/06/23 06:55:59 hugowetterberg Exp $

/**
* Database abstraction class
*/
class DrupalOAuthDataStore extends OAuthDataStore {
  /**
   * Check if consumer exists from a given consumer key.
   *
   * @param string $consumer_key
   *   The consumer key.
   * @return OAuthConsumer
   *  The consumer
   * @throws OAuthException
   *  An exception is thrown when the consumer cannot be found
   */
  function lookup_consumer($consumer_key) {
    $consumer = DrupalOAuthConsumer::load($consumer_key);
    if ($consumer) {
      return $consumer;
    }
    throw new OAuthException('Consumer not found');
  }

  /**
   * Check if the token exists.
   *
   * @param OAuthConsumer $consumer
   *  The consumer.
   * @param string $token_type
   *  The type of the token: 'request' or 'access'.
   * @param string $token
   *  The token key.
   * @return DrupalOauthToken
   *  The matching token
   * @throws OAuthException
   *  An exception is thrown when the token cannot be found or doesn't match
   */
  function lookup_token($consumer, $token_type, $token) {
    $token = DrupalOAuthToken::load($token);
    if ($token) {
      if ($token->type==$token_type && $token->consumer_key==$consumer->key) {
        return $token;
      }
      throw new OAuthException('No matching token was found, token type or consumer key mismatch');
    }
    throw new OAuthException('Token not found');
  }

  /**
   * Check if the nonce value exists. If not, generate one.
   *
   * @param OAuthConsumer $consumer
   *   The service consumer information with both key
   *   and secret values.
   * @param OAuthToken $token
   *   The current token.
   * @param string $nonce
   *   A new nonce value, in case a one doesn't current exit.
   * @param int $timestamp
   *   The current time.
   * @return string
   *   The existing nonce value or NULL in
   *   case it doesn't exist.
   */
  function lookup_nonce($consumer, $token, $nonce, $timestamp) {
    $stored_nonce = db_result(db_query(
      "SELECT nonce FROM {oauth_common_nonce}
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
      drupal_write_record('oauth_common_nonce', $values);
      return NULL;
    }

    return $stored_nonce;
  }

  /**
   * Generate a new request token.
   *
   * @param OAuthConsumer $consumer
   *  The consumer to generate a token for.
   * @return DrupalOAuthToken
   *  The request token
   */
  function new_request_token($consumer) {
    $token = new DrupalOAuthToken(user_password(32), user_password(32), array(
      'consumer_key'    => $consumer->key,
      'type'            => 'request',
      'uid'             => 0,
      'expires'         => time() + variable_get('oauth_common_request_token_lifetime', 7200),
    ));
    $token->write();
    return $token;
  }

  /**
   * Generate a new access token and delete the old request token.
   *
   * @param DrupalOAuthToken $token_old
   *   The old request token.
   * @param OAuthConsumer $consumer
   *   The service consumer information.
   */
  function new_access_token($token_old, $consumer) {
    module_load_include('inc', 'oauth_common');

    if ($token_old && $token_old->authorized) {
      $token_new = new DrupalOAuthToken(user_password(32), user_password(32), array(
        'type'            => 'access',
        'uid'             => $token_old->uid,
        'consumer_key'    => $consumer->key,
        'services'        => $token_old->services,
        'authorized'      => 1,
      ));
      $token_old->delete();
      $token_new->write();
      return $token_new;
    }

    throw new OAuthException('Invalid request token');
  }
}