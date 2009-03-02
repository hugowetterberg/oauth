<?php
// $Id$

/**
 * Sets the global user object to the user associated
 * with the provided token.
 *
 * @param OAuthToken $token
 * @return void
 */
function services_oauth_set_user($token=NULL) {
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