<?php
// $Id: oauth_common.pages.inc,v 1.6 2010/02/20 22:37:03 hugowetterberg Exp $

function _oauth_common_validate_request_callback($type, $unsigned=NULL) {
  try {
    module_load_include('inc', 'oauth_common');

    list($signed, $consumer, $token) = oauth_common_verify_request();

    if ($consumer==NULL) {
      throw new OAuthException('Missing consumer token');
    }

    if (!$signed && $unsigned!='unsigned') {
      throw new OAuthException('The request wasn\'t signed');
    }

    if ($token==NULL && $type=='access token') {
      throw new OAuthException('Missing access token');
    }
  }
  catch (OAuthException $e) {
    drupal_set_header('HTTP/1.0 401 Unauthorized: ' . $e->getMessage());
    drupal_set_header(sprintf('WWW-Authenticate: OAuth realm="%s"', url('', array('absolute'=>TRUE))));
  }
  exit;
}

function _oauth_common_authorized() {
  // If we have a outh_token we're acting as a consumer and just got authorized
  if (!empty($_GET['oauth_token'])) {
    $request_token = DrupalOAuthToken::load($_GET['oauth_token'], FALSE);
    if ($request_token) {
      $consumer_token = DrupalOAuthConsumer::load($request_token->consumer_key, FALSE);
      $client = new DrupalOAuthClient($consumer_token, $request_token);

      $access_token = $client->getAccessToken();
      if ($access_token) {
        $access_token->write();
        $request_token->delete();
      }
      module_invoke_all('oauth_common_authorized', $consumer_token, $access_token, $request_token);
    }
  }
  return t('The application has been authorized');
}

/**
 * Form for granting access to the consumer
 */
function _oauth_common_authorize() {
  module_load_include('inc', 'oauth_common');
  $req = DrupalOAuthRequest::from_request();
  $context = oauth_common_context_from_request($req);
  $token = $req->get_parameter('oauth_token');
  $callback = $req->get_parameter('oauth_callback');
  $token = DrupalOAuthToken::load($token, TRUE);

  // Check that we have a valid token
  if (!$token) {
    drupal_set_message(t('Please include a valid OAuth token in your request.'), 'error');
    return;
  }

  $consumer = DrupalOAuthConsumer::load($token->consumer_key, TRUE);

  // Redirect to the right form, or present an error.
  global $user;
  if ($user->uid) {
    // There's some strange bug in the ?destination=... handling
    // This is not exactly beautiful, but it gets the work done
    // TODO: Find out why!
    if(drupal_substr($_SERVER['REQUEST_URI'], 0, 2)=='//') {
      header('Location: ' . drupal_substr($_SERVER['REQUEST_URI'], 1), TRUE, 302);
    }

    if (!(user_access('oauth authorize any consumers') || user_access('oauth authorize consumers in ' . $consumer->context))) {
      drupal_set_message(t('You are not authorized to allow external services access to this system.'), 'error');
      return drupal_access_denied();
    }

    $tvars = array(
      '@appname' => $consumer->name,
      '@user' => $user->name,
      '@appname' => $consumer->name,
      '@sitename' => variable_get('site_name', ''),
    );

    $title = !empty($context->title) ? $context->title : 'Authorize @appname';
    drupal_set_title(t($title, $tvars));

    $form = array();
    $form['oauth_parameters'] = array(
      '#type'   => 'value',
      '#value'  => serialize($req->get_parameters()),
    );

    $form['oauth_consumer'] = array(
      '#type'   => 'value',
      '#value'  => $consumer->key,
    );

    $message = !empty($context->authorization_options['message']) ? $context->authorization_options['message'] :
      'The application @appname wants to access @sitename on your behalf, check the permissions that you would like the application to have.';
    $form['message'] = array(
      '#type' => 'item',
      '#value' => t($message, $tvars),
    );

    $message = !empty($context->authorization_options['warning']) ? $context->authorization_options['warning'] :
      'If you don\'t know what @appname is, or don\'t want to give it access to your content, just click here and we\'ll take you away from this page without granting @appname any access to @sitename.';
    $form['warning'] = array(
      '#type' => 'item',
      '#value' => l(t($message, $tvars), 'oauth/authorization/deny/' . $token->key),
      '#attributes' => array(
        'class' => 'abort-authorization',
      ),
    );

    $disable_selection = !empty($context->authorization_options['disable_auth_level_selection']) && !empty($context->authorization_options['default_authorization_levels']) && $context->authorization_options['disable_auth_level_selection'];
    if (!$disable_selection) {
      $authorization_title = !empty($context->authorization_options['authorization_title']) ? $context->authorization_options['authorization_title'] :
        'Permissions';
      $form['authorization'] = array(
        '#type' => 'fieldset',
        '#title' => t($authorization_title, $tvars),
        '#options' => $auth_levels,
      );

      $form['authorization']['levels'] = array(
        '#tree' => TRUE,
      );
      foreach ($context->authorization_levels as $name => $level) {
        $auth_opt = array(
          '#type' => 'checkbox',
          '#title' => t($level->title, $tvars),
          '#description' => t($level->description, $tvars),
        );
        $form['authorization']['levels'][$name] = $auth_opt;
      }
    }
    else {
      $form['authorization']['levels'] = array(
        '#tree' => TRUE,
      );
      foreach ($context->authorization_options['default_authorization_levels'] as $level) {
        $form['authorization']['levels'][$level] = array(
          '#type' => 'value',
          '#value' => $level,
        );
      }
    }

    $deny_title = !empty($context->authorization_options['deny_access_title']) ? $context->authorization_options['deny_access_title'] :
      'Deny access';
    $form['deny'] = array(
      '#type'   => 'item',
      '#value'  => l(t($deny_title), 'oauth/authorization/deny/' . $token->key),
      '#attributes' => array(
        'class' => 'deny-access',
      ),
    );

    $grant_title = !empty($context->authorization_options['grant_access_title']) ? $context->authorization_options['grant_access_title'] :
      'Grant access';
    $form['confirm'] = array(
      '#type'   => 'submit',
      '#value'  => t($grant_title),
    );

    return $form;
  }
  else {
    $query = $_GET;
    unset($query['q']); // why are there so few q's?
    drupal_goto('user/login', array(
      'destination' => url('oauth/authorize', array(
        'query' => $query,
        'absolute' => TRUE,
      )),
    ));
  }
}

function _oauth_common_authorize_validate($form, &$form_state) {
  $values = $form_state['values'];
  $got_permission = FALSE;

  $consumer = DrupalOAuthConsumer::load($values['oauth_consumer'], TRUE);
  $context = oauth_common_context_load($consumer->context);

  foreach ($context->authorization_levels as $name => $level) {
    if ($values['levels'][$name]) {
      $got_permission = TRUE;
      break;
    }
  }

  $got_permission = $got_permission || $values['full_access']; // TODO: Full access should be a configurable auth level

  if (!$got_permission) {
    form_set_error('confirm', t('You haven\'t given the application access to anything. Click on "Deny access" or just close this window if you don\'t want to authorize it.'));
  }
}

function _oauth_common_authorize_submit(&$form, &$form_state) {
  global $user;
  $values = $form_state['values'];
  // Unserialize the stored oauth parameters
  $parameters = unserialize($values['oauth_parameters']);

  // Save the list of all services that the user allowed the
  // consumer to do
  $token = DrupalOAuthToken::load($parameters['oauth_token'], TRUE);
  $token->uid = $user->uid;
  $token->authorized = 1;
  $token->services = array();
  $consumer = DrupalOAuthConsumer::load($token->consumer_key, TRUE);
  $context = oauth_common_context_load($consumer->context);

  // Add services
  if ($values['full_access']) { // TODO: Full access should be a configurable auth level
    $token->services[] = '*';
  }
  else {
    foreach ($context->authorization_levels as $name => $level) {
      if ($values['levels'][$name]) {
        $token->services[] = $name;
      }
    }
  }

  $token->write(TRUE);

  $got_permission = $got_permission || $values['full_access']; // TODO: Full access should be a configurable auth level

  if (!empty($consumer->callback_url)) {
    // Pick the callback url apart and add the token parameter
    $callback = parse_url($consumer->callback_url);
    $query = array();
    parse_str($callback['query'], $query);
    $query['oauth_token'] = $token->key;
    $callback['query'] = http_build_query($query, 'idx_', '&');

    // Return to the consumer site
    header('Location: ' . _oauth_common_glue_url($callback), TRUE, 302);
    exit;
  }
  else {
    drupal_goto('oauth/authorized');
  }
}

function _oauth_common_glue_url($parsed) {
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
function _oauth_common_request_token() {
  try {
    $req = DrupalOAuthRequest::from_request();
    $server = new DrupalOAuthServer(oauth_common_context_from_request($req));
    print $server->fetch_request_token($req);
  }
  catch (OAuthException $e) {
    drupal_set_header('HTTP/1.0 401 Unauthorized: ' . $e->getMessage());
    drupal_set_header(sprintf('WWW-Authenticate: OAuth realm="%s"', url('', array('absolute'=>TRUE))));
  }
}

/**
 * Get a access token for the request
 */
function _oauth_common_access_token() {
  try {
    $req = DrupalOAuthRequest::from_request();
    $context = oauth_common_context_from_request($req);
    $server = new DrupalOAuthServer($context);
    $access_token = $server->fetch_access_token($req);

    // Set the expiry time based on context settings or get parameter
    $expires = !empty($context->authorization_options['access_token_lifetime']) ? time() + $context->authorization_options['access_token_lifetime'] : 0;
    if ($_GET['expires'] && intval($_GET['expires'])) {
      $hint = intval($_GET['expires']);
      // Only accept more restrictive expiry times
      if ($expires == 0 || $hint < $expires) {
        $expires = $hint;
      }
    }

    // Store the expiry time if the access token should expire
    if ($expires) {
      $access_token->expires = $expires;
      $access_token->write(TRUE);
    }

    print $access_token;
  }
  catch (OAuthException $e) {
    drupal_set_header('HTTP/1.0 401 Unauthorized: ' . $e->getMessage());
    drupal_set_header(sprintf('WWW-Authenticate: OAuth realm="%s"', url('', array('absolute'=>TRUE))));
  }
}

function _oauth_common_user_applications($form_state, $account) {
  drupal_set_title(check_plain($account->name));
  module_load_include('inc', 'oauth_common');

  $form = array(
    'uid' => array(
      '#type' => 'value',
      '#value' => $account->uid,
    ),
  );
  $can_register_consumers = user_access('oauth register any consumers');
  if (!$can_register_consumers) {
    foreach(oauth_common_context_load_all() as $context) {
      $can_register_consumers = $can_register_consumers || user_access(sprintf('oauth register consumers in %s', $context->name));
    }
  }
  $ci = oauth_common_user_consumers($account->uid, TRUE);
  if (!empty($ci) || $can_register_consumers) {
    $apps = array(
      '#type' => 'fieldset',
      '#title' => t('Applications'),
    );

    if (!empty($ci)) {
      foreach ($ci as $consumer) {
        $apps[$consumer->key] = array(
          '#prefix' => '<div class="consumer-application"><h3>' . check_plain($consumer->name) . '</h3>',
          '#suffix' => '</div>',
          'context' => array(
            '#type' => 'item',
            '#title' => t('Context'),
            '#value' => $consumer->context,
          ),
          'edit' => array(
            '#type' => 'item',
            '#value' => l(t('Edit'), 'user/' . $account->uid . '/applications/' . $consumer->key . '/edit'),
          ),
          'delete' => array(
            '#type' => 'item',
            '#value' => l(t('Delete'), 'user/' . $account->uid . '/applications/' . $consumer->key . '/delete'),
          ),
        );
      }
    }

    if ($can_register_consumers) {
      $apps['create_consumer'] = array(
        '#type' => 'submit',
        '#value' => 'Add application',
      );
    }

    $form['applications'] = $apps;
  }

  if (user_access('oauth authorize consumers', $account)) {
    $auth = array(
      '#type' => 'fieldset',
      '#title' => t('Authorizations'),
    );

    $tokens = oauth_common_user_access_tokens($account->uid);
    $consumers = array();
    foreach ($tokens as $token) {
      if (!isset($consumers[$token->consumer_key])) {
        $consumers[$token->consumer_key] = DrupalOAuthConsumer::load($token->consumer_key, TRUE);
      }
      $consumer = $consumers[$token->consumer_key];

      $auth[$token->key] = array(
        '#prefix' => '<div class="consumer-authorization">',
        '#suffix' => '</div>',
        'consumer_name' => array(
          '#type' => 'item',
          '#title' => t('Application'),
          '#value' => check_plain($consumer->name),
        ),
        'access_key' => array(
          '#type' => 'item',
          '#title' => t('Token key'),
          '#value' => $token->key,
        ),
        'remove_link' => array(
          '#type' => 'item',
          '#value' => l('Edit authorization', 'user/' . $account->uid .
            '/applications/authorization/' . $token->key),
        ),
      );
    }

    $form['authorizations'] = $auth;
  }

  return $form;
}

function _oauth_common_user_applications_submit($form, $form_state) {
  // Send the user to the application creation form
  if ($form_state['clicked_button']['#id']=='edit-create-consumer') {
    drupal_goto(sprintf('user/%d/applications/add', $form_state['values']['uid']));
  }
}

function _oauth_common_user_applications_edit($form_state, $user, $consumer_key) {
  // Get app info
  $consumer = DrupalOAuthConsumer::load($consumer_key);

  $form['name'] = array(
    '#type' => 'item',
    '#value' => check_plain($consumer->name),
    '#prefix' => '<h3>',
    '#suffix' => '</h3>',
  );

  $form['context'] = array(
    '#type' => 'item',
    '#title' => t('Context'),
    '#value' => check_plain($consumer->context),
  );

  $form['created'] = array(
    '#type' => 'item',
    '#title' => t('Created'),
    '#value' => format_date($consumer->created, 'medium'),
  );

  $form['edited'] = array(
    '#type' => 'item',
    '#title' => t('Edited'),
    '#value' => format_date($consumer->changed, 'medium'),
  );

  $form['consumer_key'] = array(
    '#type' => 'item',
    '#title' => t('Consumer key'),
    '#value' => $consumer->key,
  );

  $form['consumer_key_send'] = array(
    '#type' => 'value',
    '#value' => $consumer->key,
  );

  $form['consumer_secret'] = array(
    '#type' => 'item',
    '#title' => t('Consumer secret'),
    '#value' => $consumer->secret,
  );

  $form['callback_url'] = array(
    '#type' => 'textfield',
    '#title' => t('Callback URL'),
    '#default_value' => isset($consumer->callback_url) ? $consumer->callback_url : '',
  );

  $form['save'] = array(
    '#type' => 'submit',
    '#title' => t('Save'),
    '#default_value' => t('Save'),
  );

  return $form;
}

function _oauth_common_user_applications_edit_submit($form, &$form_state) {
  // Add scheme if missing
  if (preg_match('/^http:\/\/|https:\/\//', $form_state['values']['callback_url']) === 0) {
    $form_state['values']['callback_url'] = 'http://' . $form_state['values']['callback_url'];
  }

  // Remove trailing slash
  $form_state['values']['callback_url'] = rtrim($form_state['values']['callback_url'], '/');

  $consumer = DrupalOAuthConsumer::load($form_state['values']['consumer_key_send']);
  $consumer->callback_url = $form_state['values']['callback_url'];
  $consumer->write(TRUE);
}

function _oauth_common_user_applications_delete($form_state, $user, $consumer_key) {
  $consumer = DrupalOAuthConsumer::load($consumer_key);
  $form = array(
    'confirm' => array(
      '#type' => 'item',
      '#value' => t('Are you sure you want to delete application <strong>@a</strong>?', array('@a' => $consumer->name)),
    ),
    'consumer_key' => array(
      '#type' => 'value',
      '#value' => $consumer->key,
    ),
    'save' => array(
      '#type' => 'submit',
      '#title' => t('Delete'),
      '#default_value' => t('Delete'),
    ),
  );

  return $form;
}

function _oauth_common_user_applications_delete_submit($form, &$form_state) {
  $consumer = DrupalOAuthConsumer::load($form_state['values']['consumer_key'] );
  $consumer->delete();

  drupal_goto('user/' . $consumer->uid . '/applications');
}

function _oauth_common_user_authorization_edit($form_state, $user, $key) {
  $form = array();

  $token = DrupalOAuthToken::load($key, TRUE);
  $consumer = DrupalOAuthConsumer::load($token->consumer_key);

  drupal_set_title(t('Authorization for @app', array('@app' => $consumer->name)));

  $form['user'] = array(
    '#type' => 'value',
    '#value' => $user->uid,
  );

  $form['key'] = array(
    '#type' => 'value',
    '#value' => $token->key,
  );

  $form['authorized'] = array(
    '#type' => 'checkbox',
    '#title' => t('Authorized'),
    '#default_value' => $token->authorized,
  );

  $form['created'] = array(
    '#type' => 'item',
    '#title' => t('Created'),
    '#value' => format_date($token->created),
  );

  $form['changed'] = array(
    '#type' => 'item',
    '#title' => t('Changed'),
    '#value' => format_date($token->changed),
  );

  $form['key_item'] = array(
    '#type' => 'item',
    '#title' => t('Key'),
    '#value' => $token->key,
  );

  $form['allowed'] = array(
    '#type' => 'fieldset',
    '#title' => t('Permissions'),
  );

  oauth_common_permissions_form($user, $form['allowed'], $consumer, $token->services);

  $form['delete'] = array(
    '#type' => 'item',
    '#value' => l(t('Delete'), sprintf('user/%d/applications/authorization/%s/delete', $user->uid, $token->key)),
  );

  $form['submit'] = array(
    '#type' => 'submit',
    '#value' => t('Save'),
  );

  return $form;
}

function _oauth_common_user_authorization_edit_submit($form, $form_state) {
  $values = $form_state['values'];

  // Collect the authorization levels
  $services = array();
  foreach ($values['levels'] as $level => $allowed) {
    if ($allowed) {
      $services[] = $level;
    }
  }

  $token = DrupalOAuthToken::load($values['key'], TRUE);
  $consumer = DrupalOAuthConsumer::load($token->consumer_key);

  $token->services = $services;
  $token->authorized = $values['authorized'];
  $token->write(TRUE);

  drupal_set_message(t('The @consumer token @token was updated.', array(
    '@consumer' => $consumer->name,
    '@token' => $token->key)));
  drupal_goto(sprintf('user/%d/applications', $form_state['values']['user']));
}

function _oauth_common_user_authorization_delete($form_state, $user, $key) {
  $token = DrupalOAuthToken::load($key, TRUE);
  $consumer = DrupalOAuthConsumer::load($token->consumer_key);

  drupal_set_title(t('Deleting authorization for "@title"', array(
    '@title' => $consumer->name,
  )));

  $form = array(
    'authorization' => array(
      '#type' => 'value',
      '#value' => $authorization,
    ),
  );

  $form['user'] = array(
    '#type' => 'value',
    '#value' => $user->uid,
  );

  $form['key'] = array(
    '#type' => 'value',
    '#value' => $token->key,
  );

  $form['description'] = array(
    '#type' => 'item',
    '#value' => t('Are you sure that you want to delete the authorization for @name?', array(
      '@name' => $consumer->name,
    )),
  );

  $form['cancel'] = array(
    '#type' => 'item',
    '#value' => l(t('Cancel'), sprintf('user/%d/applications/authorization/%s', $user->uid, $token->key)),
  );

  $form['submit'] = array(
    '#type' => 'submit',
    '#value' => t('Delete'),
  );

  return $form;
}

function _oauth_common_user_authorization_delete_submit($form, $form_state) {
  $token = DrupalOAuthToken::load($form_state['values']['key'], TRUE);
  $consumer = DrupalOAuthConsumer::load($token->consumer_key);
  $token->delete();
  drupal_set_message(t('The @consumer token @token was deleted.', array(
    '@consumer' => $consumer->name,
    '@token' => $token->key)));
  drupal_goto(sprintf('user/%d/applications', $form_state['values']['user']));
}

function oauth_common_permissions_form($account, &$form, $consumer, $default_services=array('*')) {
  $tvars = array(
    '@appname' => $consumer->name,
    '@user' => $account->name,
    '@sitename' => variable_get('site_name', ''),
  );

  $auth_levels = oauth_common_authorization_levels($consumer->context);

  foreach ($auth_levels as $name => $level) {
    $auth_opt = array(
      '#type' => 'checkbox',
      '#title' => t($level->title, $tvars),
      '#description' => t($level->description, $tvars),
      '#default_value' => in_array($name, $default_services),
    );
    $form['authorization']['levels'][$name] = $auth_opt;
  }
}

function _oauth_common_user_applications_add($form_state, $account) {
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

  $form['callback_url'] = array(
    '#type' => 'textfield',
    '#title' => t('Callback url'),
    '#required' => FALSE,
  );

  $allowed_contexts = array();
  foreach(oauth_common_context_list() as $context => $title) {
    if (user_access(sprintf('oauth register consumers in %s', $context))) {
      $allowed_contexts[$context] = $title;
    }
  }

  $form['context'] = array(
    '#type' => 'select',
    '#title' => t('Application context'),
    '#options' => $allowed_contexts,
  );

  $form['submit'] = array(
    '#type' => 'submit',
    '#value' => t('Create'),
  );

  return $form;
}

function _oauth_common_user_applications_add_submit($form, $form_state) {
  // Add scheme if missing
  if (preg_match('/^http:\/\/|https:\/\//', $form_state['values']['callback_url']) === 0) {
    $form_state['values']['callback_url'] = 'http://' . $form_state['values']['callback_url'];
  }

  // Remove trailing slash
  $form_state['values']['callback_url'] = rtrim($form_state['values']['callback_url'], '/');

  $v = $form_state['values'];
  $consumer = new DrupalOAuthConsumer(user_password(32), user_password(32), $v['callback_url'], TRUE, $v);
  $consumer->write();

  drupal_set_message(t('Added the application @name', array('@name' => $v['name'])));
  drupal_goto(sprintf('user/%d/applications', $v['uid']));
}