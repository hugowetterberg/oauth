<?php
// $Id$

/**
 * Return information about consumers related to a user.
 *
 * @param int $uid
 *  User ID to retrieve consumer info for.
 * @return array
 *  An array of consumer info
 */
function services_oauth_user_consumers($uid) {
  $result = db_query('SELECT * FROM {services_oauth_consumer} WHERE uid = %d', array(
    ':uid' => $uid,
  ));
  $consumers = array();
  while ($consumer = db_fetch_object($result)) {
    $consumers[] = $consumer;
  }
  return $consumers;
}

/**
 * Creates a consumer
 *
 * @param int $uid
 *  The user that owns the consumer
 * @param string $name
 *  The name of the consumer
 * @param string $type
 *  The type of the consumer
 * @return string
 *  The consumer key
 */
function services_oauth_create_consumer($uid, $name, $type) {
  $token = new OAuthToken(user_password(32), user_password(32));
  $values = array(
    'consumer_key' => $token->key,
    'consumer_secret' => $token->secret,
    'uid' => $uid,
    'name' => $name,
    'type' => $type,
  );
  drupal_write_record('services_oauth_consumer', $values);

  return $token->key;
}

/**
 * Gets the token with the specified key
 *
 * @param string $key
 *  The key of the token to get
 */
function services_oauth_get_token($key) {
  return db_fetch_object(db_query("SELECT * FROM {services_oauth_token} WHERE token_key='%s'", array(
    ':token_key' => $key,
  )));
}