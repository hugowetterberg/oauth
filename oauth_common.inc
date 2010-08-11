<?php
// $Id$

/**
 * Return information about consumers related to a user.
 *
 * @param int $uid
 *  User ID to retrieve consumer info for.
 * @param mixed $provider_consumer
 *  Optional. Pass TRUE or FALSE to load either provider or consumer consumers.
 *  Omit or pass NULL to get both.
 * @return array
 *  An array of consumer info
 */
function oauth_common_user_consumers($uid, $provider_consumer = NULL) {
  $query = 'SELECT * FROM {oauth_common_consumer}
    WHERE uid = %d';
  $args = array(
    ':uid' => $uid,
  );
  if ($provider_consumer !== NULL) {
    $query .= '
    AND provider_consumer = %d';
    $args[':provider_consumer'] = $provider_consumer;
  }
  $result = db_query($query, array(
    ':uid' => $uid,
  ));
  $consumers = array();
  while ($consumer = DrupalOAuthConsumer::fromResult($result)) {
    $consumers[] = $consumer;
  }
  return $consumers;
}

/**
 * Return information about access tokens related to a user.
 *
 * @param int $uid
 *  User ID to retrieve consumer info for.
 * @return array
 *  An array of consumer info
 */
function oauth_common_user_access_tokens($uid) {
  $result = db_query("SELECT * FROM {oauth_common_token} WHERE uid = %d AND type = 'access'", array(
    ':uid' => $uid,
  ));
  $tokens = array();
  while ($token = DrupalOAuthToken::fromResult($result)) {
    $tokens[] = $token;
  }
  return $tokens;
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
  $consumer_key = $req->get_parameter('oauth_consumer_key');
  if (!empty($consumer_key)) {
    $consumer = DrupalOAuthConsumer::load($consumer_key, TRUE);
    if ($consumer) {
      $context = oauth_common_context_load($consumer->context);
      _oauth_common_verify_body_hash($req);

      // Only verify request if we got a signature
      $signature = $req->get_parameter('oauth_signature');
      if (!empty($signature)) {
        $server = new DrupalOAuthServer($context);
        return array_merge(array(TRUE), $server->verify_request($req));
      }
      else {
        $token_key = $req->get_parameter('oauth_token');
        if (empty($token_key) || !($token=DrupalOAuthToken::load($token_key, TRUE))) {
          $token = NULL;
        }
        return array(FALSE, $consumer, $token);
      }
    }
  }
  return array(FALSE, NULL,NULL);
}

/**
 * AHAH callback to retrieve the secret of OAuth objects.
 *
 * @param object $object
 * @return void
 */
function oauth_common_ahah_secret($object) {
  $cached_form_state = array();
  $form = form_get_cache($_POST['form_build_id'], $cached_form_state);
  form_set_cache($_POST['form_build_id'], $form, $cached_form_state);

  $form_state = array('submitted' => FALSE);
  $secret = array(
    '#prefix' => '',
    '#value' => $object->secret,
  ) + $form['secret'];
  $secret = form_builder('oauth_common_ahah_secret', $secret, $form_state);
  $output = drupal_render($secret);

  print drupal_to_js(array(
    'status' => TRUE,
    'data' => $output,
  ));
  exit;
}

function _oauth_common_verify_body_hash($req) {
  $body_hash = $req->get_parameter('oauth_body_hash');
  if ($body_hash) {
    $hres = hash_init('sha1');
    $stream = fopen('drupal://input', 'r');
    hash_update_stream($hres, $stream);
    fclose($stream);
    $sha1 = hash_final($hres, TRUE);
    if ($sha1 !== base64_decode($body_hash)) {
      throw new OAuthException("Invalid body hash");
    }
  }
}