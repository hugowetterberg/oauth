<?php
// $Id: oauth_common.pages.inc,v 1.2 2009/06/23 06:55:59 hugowetterberg Exp $

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
  return t('The application has been authorized');
}

/**
 * Form for granting access to the consumer
 */
function _oauth_common_authorize() {
  module_load_include('inc', 'oauth_common');
  $req = DrupalOAuthRequest::from_request();
  $token = $req->get_parameter('oauth_token');
  $callback = $req->get_parameter('oauth_callback');
  $token = DrupalOAuthToken::load($token);

  // Check that we have a valid token
  if (!$token) {
    drupal_set_message(t('Please include a valid OAuth token in your request.'), 'error');
    return;
  }

  $consumer = DrupalOAuthConsumer::load($token->consumer_key);

  // Redirect to the right form, or present an error.
  global $user;
  if ($user->uid) {
    // There's some strange bug in the ?destination=... handling
    // This is not exactly beautiful, but it gets the work done
    // TODO: Find out why!
    if(drupal_substr($_SERVER['REQUEST_URI'], 0, 2)=='//') {
      header('Location: ' . drupal_substr($_SERVER['REQUEST_URI'], 1), TRUE, 302);
    }

    if (!user_access('oauth authorize consumers')) {
      drupal_set_message(t('You are not authorized to allow external services access to this system.'), 'error');
      return drupal_access_denied();
    }

    drupal_set_title(t('Authorize !name', array(
      '!name' => $consumer->name,
    )));

    $form = array();
    $form['oauth_parameters'] = array(
      '#type'   => 'value',
      '#value'  => serialize($req->get_parameters()),
    );

    $msgargs = array(
      '!appname' => $consumer->name,
      '!sitename' => variable_get('site_name', ''),
    );

    $form['message'] = array(
      '#type' => 'item',
      '#value' => t('The application !appname wants to access !sitename on your behalf, check the permissions that you would like the application to have.', $msgargs),
    );

    $form['warning'] = array(
      '#type' => 'item',
      '#value' => l(t('If you don\'t know what !appname is, or don\'t want to give it access to your content, just click here and we\'ll take you away from this page without granting !appname any access to !sitename.', $msgargs), 'oauth/authorization/deny/' . $token->key),
      '#attributes' => array(
        'class' => 'abort-authorization',
      ),
    );

    $form['authorization'] = array(
      '#type' => 'fieldset',
      '#title' => t('Permissions'),
      '#options' => $auth_levels,
      'full_access' => array(
        '#type' => 'checkbox',
        '#title' => t('Full access'),
        '#description' => t('This will give !appname the same permissions that you normally have and will allow it to access the full range of services that !sitename provides.', $msgargs),
      ),
    );

    $auth_levels = oauth_common_authorization_levels();
    $form['authorization']['levels'] = array(
      '#tree' => TRUE,
    );
    foreach ($auth_levels as $name => $level) {
      $auth_opt = array(
        '#type' => 'checkbox',
        '#title' => t($level->title, $msgargs),
        '#description' => t($level->description, $msgargs),
      );
      $form['authorization']['levels'][$name] = $auth_opt;
    }

    $form['deny'] = array(
      '#type'   => 'item',
      '#value'  => l(t('Deny access'), 'oauth/authorization/deny/' . $token->key),
      '#attributes' => array(
        'class' => 'deny-access',
      ),
    );

    $form['confirm'] = array(
      '#type'   => 'submit',
      '#value'  => t('Grant access'),
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

  $auth_levels = oauth_common_authorization_levels();
  foreach ($auth_levels as $name => $level) {
    if ($values['levels'][$name]) {
      $got_permission = TRUE;
      break;
    }
  }

  $got_permission = $got_permission || $values['full_access'];

  if (!$got_permission) {
    form_set_error('confirm', t('You haven\'t given the application access to anything. Click on "Deny access" or just close this window if you don\'t want to authorize it.'));
  }
}

function _oauth_common_authorize_submit(&$form, &$form_state) {
  $values = $form_state['values'];
  // Unserialize the stored oauth parameters
  $parameters = unserialize($values['oauth_parameters']);

  // Save the list of all services that the user allowed the
  // consumer to do
  global $user;
  $token = DrupalOAuthToken::load($parameters['oauth_token']);
  $token->uid = $user->uid;
  $token->authorized = 1;
  $token->services = array();

  // Add services
  if ($values['full_access']) {
    $token->services[] = '*';
  }
  else {
    $auth_levels = oauth_common_authorization_levels();
    foreach ($auth_levels as $name => $level) {
      if ($values['levels'][$name]) {
        $token->services[] = $name;
      }
    }
  }

  $token->write(TRUE);

  $got_permission = $got_permission || $values['full_access'];

  if (isset($parameters['oauth_callback'])) {
    // Pick the callback url apart and add the token parameter
    $callback = parse_url($parameters['oauth_callback']);
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
 * Get a access token for the request
 */
function _oauth_common_access_token() {
  try {
    $server = new DrupalOAuthServer();
    $req = DrupalOAuthRequest::from_request();
    $access_token = $server->fetch_access_token($req);

    // Store the expiry time if specified by the client
    if ($_GET['expires'] && intval($_GET['expires'])) {
      $access_token->expires = intval($_GET['expires']);
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
  $ci = oauth_common_user_consumers($account->uid);
  if (!empty($ci) || user_access('oauth register consumers')) {
    $apps = array(
      '#type' => 'fieldset',
      '#title' => t('Applications'),
    );

    if (!empty($ci)) {
      foreach ($ci as $consumer) {
        $apps[$consumer->key] = array(
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
            '#value' => $consumer->key,
          ),
          'secret' => array(
            '#type' => 'fieldset',
            '#collapsible' => TRUE,
            '#collapsed' => TRUE,
            '#title' => t('Consumer secret'),
            'consumer_secret' => array(
              '#type' => 'item',
              '#value' => $consumer->secret,
            ),
          ),
        );
      }
    }

    if (user_access('oauth register consumers')) {
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
        $consumers[$token->consumer_key] = DrupalOAuthConsumer::load($token->consumer_key);
      }
      $consumer = $consumers[$token->consumer_key];

      $auth[$token->key] = array(
        '#prefix' => '<div class="consumer-authorization">',
        '#suffix' => '</div>',
        'consumer_name' => array(
          '#type' => 'item',
          '#title' => t('Application'),
          '#value' => $consumer->name,
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

function _oauth_common_user_authorization_edit($form_state, $user, $key) {
  $form = array();

  $token = DrupalOAuthToken::load($key);
  $consumer = DrupalOAuthConsumer::load($token->consumer_key);

  drupal_set_title(t('Authorization for !app', array('!app' => $consumer->name)));

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

  oauth_common_permissions_form($form['allowed'], $consumer, $token->services);

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

  $token = DrupalOAuthToken::load($values['key']);
  $consumer = DrupalOAuthConsumer::load($token->consumer_key);

  $token->services = $services;
  $token->authorized = $values['authorized'];
  $token->write(TRUE);

  drupal_set_message(t('The !consumer token !token was updated.', array(
    '!consumer' => $consumer->name,
    '!token' => $token->key)));
  drupal_goto(sprintf('user/%d/applications', $form_state['values']['user']));
}

function _oauth_common_user_authorization_delete($form_state, $user, $key) {
  $token = DrupalOAuthToken::load($key);
  $consumer = DrupalOAuthConsumer::load($token->consumer_key);

  drupal_set_title(t('Deleting authorization for "!title"', array(
    '!title' => $consumer->name,
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
    '#value' => t('Are you sure that you want to delete the authorization for !name?', array(
      '!name' => $consumer->name,
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
  $token = DrupalOAuthToken::load($form_state['values']['key']);
  $consumer = DrupalOAuthConsumer::load($token->consumer_key);
  $token->delete();
  drupal_set_message(t('The !consumer token !token was deleted.', array(
    '!consumer' => $consumer->name,
    '!token' => $token->key)));
  drupal_goto(sprintf('user/%d/applications', $form_state['values']['user']));
}

function oauth_common_permissions_form(&$form, $consumer, $default_services=array('*')) {
  $msgargs = array(
    '!appname' => $consumer->name,
    '!sitename' => variable_get('site_name', ''),
  );

  $auth_levels = array_merge(
    array('*' => (object)array(
      'title' => t('Full access'),
      'description' => t('This will give !appname the same permissions that you normally have and will allow it to access the full range of services that !sitename provides.', $msgargs),
    )), oauth_common_authorization_levels());
  $form['authorization']['levels'] = array(
    '#tree' => TRUE,
  );

  foreach ($auth_levels as $name => $level) {
    $auth_opt = array(
      '#type' => 'checkbox',
      '#title' => t($level->title, $msgargs),
      '#description' => t($level->description, $msgargs),
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

function _oauth_common_user_applications_add_submit($form, $form_state) {
  $v = $form_state['values'];
  $consumer = new DrupalOAuthConsumer(user_password(32), user_password(32), $v['callback_url'], $v);
  $consumer->write();

  drupal_set_message(t('Added the application !name', array('!name' => $v['name'])));
  drupal_goto(sprintf('user/%d/applications', $v['uid']));
}