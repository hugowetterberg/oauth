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
  while ($consumer = DrupalOAuthConsumer::fromResult($result)) {
    $consumers[] = $consumer;
  }
  return $consumers;
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
 *  An array containing three elements. The first is TRUE if the request was
 *  signed, otherwise FALSE. Then comes the validated consumer and token objects.
 */
function oauth_common_verify_request() {
  $req = DrupalOAuthRequest::from_request();
  // Verify
  $consumer = $req->get_parameter('oauth_consumer_key');
  if (!empty($consumer)) {
    // Only verify request if we got a signature
    $signature = $req->get_parameter('oauth_signature');
    if (!empty($signature)) {
      $server = new DrupalOAuthServer();
      return array_merge(array(TRUE), $server->verify_request($req));
    }
    else {
      $token_key = $req->get_parameter('oauth_token');
      if (empty($token_key) || !($token=DrupalOAuthToken::load($token_key))) {
        $token = NULL;
      }
      return array(FALSE, DrupalOAuthConsumer::load($consumer), $token);
    }
  }
  return array(FALSE, NULL,NULL);
}