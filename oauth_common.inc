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
function oauth_common_user_consumers($uid) {
  $result = db_query('SELECT * FROM {oauth_common_consumer} WHERE uid = %d', array(
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
function oauth_common_create_consumer($uid, $name, $type) {
  $token = new OAuthToken(user_password(32), user_password(32));
  $values = array(
    'consumer_key' => $token->key,
    'consumer_secret' => $token->secret,
    'uid' => $uid,
    'name' => $name,
    'type' => $type,
  );
  drupal_write_record('oauth_common_consumer', $values);

  return $token->key;
}

/**
 * Gets the token with the specified key
 *
 * @param string $key
 *  The key of the token to get
 */
function oauth_common_get_token($key) {
  return db_fetch_object(db_query("SELECT * FROM {oauth_common_token} WHERE token_key='%s'", array(
    ':token_key' => $key,
  )));
}

/**
 * Sets the global user object to the user associated
 * with the provided token.
 *
 * @param OAuthToken $token
 * @return void
 */
function oauth_common_set_user($token=NULL) {
  // Load the appropriate user if we got a token
  if ($token && !empty($token->key)) {
    $uid = db_result(db_query("SELECT uid
      FROM {oauth_common_token}
      WHERE token_key='%s' AND consumer_key='%s'", array(
        ':token_key' => $token->key,
        ':consumer_key' => $consumer->key,
      )));
    if ($uid) {
      global $user;
      $user = user_load(array('uid' => $uid));
    }
  }
}

/**
 * Verifies the request
 *
 * @return array
 *  An array containing the validated consumer and token
 */
function oauth_common_verify_request() {
  $req = DrupalOAuthRequest::from_request();
  // Verify
  $consumer = $req->get_parameter('oauth_consumer_key');
  if (!empty($consumer)) {
    $server = new DrupalOAuthServer();
    return $server->verify_request($req);
  }
  return array(NULL,NULL);
}