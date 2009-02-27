<?php
// $Id$

/**
 * Form for granting access to the consumer
 */
function _services_oauth_authorize() {
  module_load_include('inc', 'services_oauth');
  $req = DrupalOAuthRequest::from_request();
  $token = $req->get_parameter('oauth_token');
  $callback = $req->get_parameter('oauth_callback');
  $token = services_oauth_get_token($token);

  // Check that we have a valid token
  if (!$token) {
    drupal_set_message(t('Please include a valid OAuth token in your request.'), 'error');
    return;
  }

  // Redirect to the right form, or present an error.
  global $user;
  if ($user->uid) {
    // There's some strange bug in the ?destination=... handling
    // This is not exactly beautiful, but it gets the work done
    // TODO: Find out why!
    if(drupal_substr($_SERVER['REQUEST_URI'], 0, 2)=='//') {
      header('Location: ' . drupal_substr($_SERVER['REQUEST_URI'], 1), TRUE, 302);
    }

    if (!user_access('access services')) {
      drupal_set_message(t('You are not authorized to allow external services access to this system.'), 'error');
      return drupal_access_denied();
    }

    $form = array();
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
  else {
    drupal_goto('user/login', array(
      'destination' => url('oauth/authorize', array(
        'query' => array(
          'oauth_token' => $token->token_key,
          'oauth_callback' => $callback,
        ),
        'absolute' => TRUE,
      )),
    ));
  }
}

/**
 * Asks users for granting proper access/deny permissions for different services
 * Authorizes an existing oauth request token and redirects to sender.
 *
 * @ingroup form
 */
function _services_oauth_authorize_submit(&$form, &$form_state) {
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

  // Pick the callback url apart and add the token parameter
  $callback = parse_url($parameters['oauth_callback']);
  $query = array();
  parse_str($callback['query'], $query);
  $query['oauth_token'] = $parameters['oauth_token'];
  $callback['query'] = http_build_query($query);

  // Return to the consumer site
  header('Location: ' . _services_oauth_glue_url($callback), TRUE, 302);
  exit;
}

function _services_oauth_glue_url($parsed) {
  $uri = isset($parsed['scheme']) ? $parsed['scheme'] . '://' : '';
  $uri .= isset($parsed['user']) ? $parsed['user'] . (isset($parsed['pass']) ? ':'.$parsed['pass'] : '').'@' : '';
  $uri .= isset($parsed['host']) ? $parsed['host'] : '';
  $uri .= isset($parsed['port']) ? ':' . $parsed['port'] : '';

  if (isset($parsed['path'])) {
    $uri .= (substr($parsed['path'], 0, 1) == '/') ?
      $parsed['path'] :
      ((!empty($uri) ? '/' : '' ) . $parsed['path']);
  }

  $uri .= isset($parsed['query']) ? '?' . $parsed['query'] : '';

  return $uri;
}

/**
 * Generate a request token from the request.
 */
function _services_oauth_request_token() {
  try {
    $server = new DrupalOAuthServer();
    $req = DrupalOAuthRequest::from_request();
    print $server->fetch_request_token($req);
  }
  catch (OAuthException $e) {
    drupal_set_header('HTTP/1.0 401 Unauthorized: ' . $e->getMessage());
    drupal_set_header(sprintf('WWW-Authenticate: OAuth realm="%s"', url('', array('absolute'=>TRUE))));
  }
}

/**
 * Access the OAuth services
 */
function _services_oauth_access_token() {
  try {
    $server = new DrupalOAuthServer();
    $req = DrupalOAuthRequest::from_request();
    print $server->fetch_access_token($req);
  }
  catch (OAuthException $e) {
    drupal_set_header('HTTP/1.0 401 Unauthorized: ' . $e->getMessage());
    drupal_set_header(sprintf('WWW-Authenticate: OAuth realm="%s"', url('', array('absolute'=>TRUE))));
  }
}

function _services_oauth_user_applications($form_state, $account) {
  drupal_set_title(check_plain($account->name));
  module_load_include('inc', 'services_oauth');

  $form = array(
    'uid' => array(
      '#type' => 'value',
      '#value' => $account->uid,
    ),
  );
  $ci = services_oauth_user_consumers($account->uid);
  if (!empty($ci) || user_access('services oauth register consumers')) {
    $apps = array(
      '#type' => 'fieldset',
      '#title' => t('Applications'),
    );

    if (!empty($ci)) {
      foreach ($ci as $consumer) {
        $apps[$consumer->consumer_key] = array(
          '#prefix' => '<div class="consumer-application"><h3>' . $consumer->name . '</h3>',
          '#suffix' => '</div>',
          'type' => array(
            '#type' => 'item',
            '#title' => t('Type'),
            '#value' => $consumer->type,
          ),
          'consumer_key' => array(
            '#type' => 'item',
            '#title' => t('Consumer key'),
            '#value' => $consumer->consumer_key,
          ),
          'secret' => array(
            '#type' => 'fieldset',
            '#collapsible' => TRUE,
            '#collapsed' => TRUE,
            '#title' => t('Consumer secret'),
            'consumer_secret' => array(
              '#type' => 'item',
              '#value' => $consumer->consumer_secret,
            ),
          ),
        );
      }
    }

    if (user_access('services oauth register consumers')) {
      $apps['create_consumer'] = array(
        '#type' => 'submit',
        '#value' => 'Add application',
      );
    }

    $form['applications'] = $apps;
  }

  if (user_access('access services', $account)) {
    $auth = array(
      '#type' => 'fieldset',
      '#title' => t('Authorizations'),
    );
    $form['authorizations'] = $auth;
  }

  return $form;
}

function _services_oauth_user_applications_submit($form, $form_state) {
  // Send the user to the application creation form
  if ($form_state['clicked_button']['#id']=='edit-create-consumer') {
    drupal_goto(sprintf('user/%d/applications/add', $form_state['values']['uid']));
  }
}

function _services_oauth_user_applications_add($form_state, $account) {
  $form = array();

  $form = array(
    'uid' => array(
      '#type' => 'value',
      '#value' => $account->uid,
    ),
  );

  $form['name'] = array(
    '#type' => 'textfield',
    '#title' => t('Application name'),
    '#required' => TRUE,
  );

  $form['type'] = array(
    '#type' => 'select',
    '#title' => t('Application type'),
    '#options' => array(
      'community' => t('Community'),
      'commercial' => t('Commercial'),
      'development' => t('Development'),
    ),
  );

  $form['submit'] = array(
    '#type' => 'submit',
    '#value' => t('Create'),
  );

  return $form;
}

function _services_oauth_user_applications_add_submit($form, $form_state) {
  module_load_include('inc', 'services_oauth');

  $v = $form_state['values'];
  $key = services_oauth_create_consumer($v['uid'], $v['name'], $v['type']);
  drupal_set_message(t('Added the application !name', array('!name' => $v['name'])));
  drupal_goto(sprintf('user/%d/applications', $v['uid']));
}