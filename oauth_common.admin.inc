<?php
// $Id: oauth_common.admin.inc,v 1.3 2010/02/05 21:55:00 hugowetterberg Exp $

function _oauth_common_admin() {
  $form = array();

  $form['oauth_common_enable_provider'] = array(
    '#type' => 'checkbox',
    '#title' => t('Enable the oauth provider'),
    '#default_value' => variable_get('oauth_common_enable_provider', TRUE),
    '#description' => t('This option controls whether this site should act as a OAuth provider or not'),
  );

  $form['oauth_common_request_token_lifetime'] = array(
    '#type' => 'textfield',
    '#title' => t('Request token lifetime (in seconds)'),
    '#default_value' => variable_get('oauth_common_request_token_lifetime', 7200),
  );

  $form['#validate'][] = '_oauth_common_admin_settings_validate';

  return system_settings_form($form);
}

function _oauth_common_admin_settings_validate($form, $form_state) {
  $values = $form_state['values'];

  $lifetime = intval($values['oauth_common_request_token_lifetime'], 10);
  if (!$lifetime) {
    form_set_error('oauth_common_request_token_lifetime', t('The request token lifetime must be a non-zero integer value.'));
  }
}

/**
 * Output a list of contexts.
 */
function oauth_common_list_context($js = NULL) {
  $header = array(
    array('data' => t('Title'),          'class' => 'oauth-common-contexts-title'),
    array('data' => t('Storage'),        'class' => 'oauth-common-contexts-storage'),
    array('data' => t('Operations'),     'class' => 'oauth-common-contexts-operations'),
  );

  $contexts = oauth_common_context_load_all();
  $rows = array();

  foreach ($contexts as $context) {
    $operations = array();

    if (empty($context->disabled)) {
      $operations[] = array(
        'title' => t('Edit'),
        'href'  => 'admin/settings/oauth/' . $context->name . '/edit',
      );
      $operations[] = array(
        'title' => t('Export'),
        'href'  => 'admin/settings/oauth/' . $context->name . '/export',
      );
    }

    if ($context->export_type == (EXPORT_IN_CODE | EXPORT_IN_DATABASE)) {
      $operations[] = array(
        'title' => t('Revert'),
        'href'  => 'admin/settings/oauth/' . $context->name . '/delete',
      );
    }
    elseif ($context->export_type != EXPORT_IN_CODE) {
      $operations[] = array(
        'title' => t('Delete'),
        'href'  => 'admin/settings/oauth/' . $context->name . '/delete',
      );
    }
    elseif (empty($context->disabled)) {
      $operations[] = array(
        'title' => t('Disable'),
        'href'  => 'admin/settings/oauth/' . $context->name . '/disable',
        'query' => drupal_get_destination(),
      );
    }
    else {
      $operations[] = array(
        'title' => t('Enable'),
        'href'  => 'admin/settings/oauth/' . $context->name . '/enable',
        'query' => drupal_get_destination(),
      );
    }

    $rows[$context->name] = array(
      'data' => array(
        'title' => array(
          'data'  => $context->title,
          'class' => 'oauth-common-contexts-title',
        ),
        'storage' => array(
          'data'  => ($context->export_type == EXPORT_IN_CODE) ? t('In code') : t('In database'),
          'class' => 'oauth-common-contexts-storage',
        ),
        'operations' => array(
          'data'  => theme('links', $operations),
          'class' => 'oauth-common-contexts-operations',
        ),
      ),
      'class' => 'oauth-common-contexts-' . $context->name . (!empty($context->disabled) ? ' oauth-common-contexts-disabled' : ''),
    );
  }

  $table = theme('table', $header, $rows, array('id' => 'oauth-common-list-contexts'));

  return $table;
}

/**
 * Handle the add context page.
 */
function oauth_common_add_context() {
  $context = oauth_common_context_new();
  drupal_set_title(t('Add context'));
  return oauth_common_edit_context($context);
}

/**
 * Edit an context.
 *
 * Called from both the add and edit points to provide for common flow.
 */
function oauth_common_edit_context($context) {
  if (!is_object($context)) {
    $context = oauth_common_context_load($context);
  }
  if ($context && !empty($context->title)) {
    drupal_set_title(check_plain($context->title));
  }
  return drupal_get_form('oauth_common_edit_form_context', $context);
}

/**
 * Form to edit the settings of an context.
 */
function oauth_common_edit_form_context(&$form_state, $context) {
  $form = array();

  $form['cid'] = array(
    '#type'  => 'value',
    '#value' => isset($context->cid) ? $context->cid : '',
  );

  $form['context_object'] = array(
    '#type'  => 'value',
    '#value' => $context,
  );

  $form['name'] = array(
    '#type'          => 'textfield',
    '#size'          => 24,
    '#maxlength'     => 255,
    '#default_value' => $context->name,
    '#title'         => t('Context name'),
    '#description'   => t('A unique name used to identify this preset internally. It must be only be alpha characters and underscores. No spaces, numbers or uppercase characters.'),
    '#required'      => TRUE,
  );

  $form['title'] = array(
    '#type'          => 'textfield',
    '#size'          => 24,
    '#maxlength'     => 255,
    '#default_value' => $context->title,
    '#title'         => t('Context title'),
    '#required'      => TRUE,
  );

  $sign_methods = array(
    'PLAINTEXT' => t('Plaintext'),
  );
  foreach (hash_algos() as $algo) {
    $sign_methods['HMAC-' . strtoupper($algo)] = 'HMAC-' . strtoupper($algo);
  }

  $form['signature_methods'] = array(
    '#type' => 'fieldset',
    '#title' => t('Signature methods'),
    '#collapsible' => TRUE,
    '#collapsed' => TRUE,
    '#tree' => TRUE,
    'selected' => array(
      '#type' => 'checkboxes',
      '#title' => t('Supported signature methods'),
      '#options' => $sign_methods,
      '#default_value' => !empty($context->authorization_options['signature_methods']) ?
         $context->authorization_options['signature_methods']:
         array('HMAC-SHA1', 'HMAC-SHA256', 'HMAC-SHA384', 'HMAC-SHA512'),
    )
  );

  $form['authorization_options'] = array(
    '#type' => 'fieldset',
    '#title' => t('Authorization options'),
    '#tree' => TRUE,
    '#collapsible' => TRUE,
    '#collapsed' => TRUE,
  );

  $form['authorization_options']['page_title'] = array(
    '#type' => 'textfield',
    '#title' => t('Page title'),
    '#description' => t('The title of the authorization page.'),
    '#size' => 40,
    '#maxlength' => 255,
    '#default_value' => $context->authorization_options['page_title'],
  );

  $form['authorization_options']['message'] = array(
    '#type' => 'textarea',
    '#title' => t('Message'),
    '#description' => t('The message shown to the user when authorizing.'),
    '#default_value' => $context->authorization_options['message'],
  );

  $form['authorization_options']['warning'] = array(
    '#type' => 'textarea',
    '#title' => t('Warning'),
    '#description' => t('The warning shown to the user when authorizing.'),
    '#default_value' => $context->authorization_options['warning'],
  );

  $form['authorization_options']['deny_access_title'] = array(
    '#type' => 'textfield',
    '#title' => t('Deny access title'),
    '#description' => t('The title of deny access link.'),
    '#size' => 40,
    '#maxlength' => 255,
    '#default_value' => $context->authorization_options['deny_access_title'],
  );

  $form['authorization_options']['grant_access_title'] = array(
    '#type' => 'textfield',
    '#title' => t('Grant access title'),
    '#description' => t('The title of grant access button.'),
    '#size' => 40,
    '#maxlength' => 255,
    '#default_value' => $context->authorization_options['grant_access_title'],
  );

  $form['authorization_options']['access_token_lifetime'] = array(
    '#type' => 'textfield',
    '#title' => t('Access token lifetime'),
    '#description' => t('The time, in seconds, for which an access token should be valid, use 0 to never expire access tokens.'),
    '#size' => 10,
    '#maxlength' => 255,
    '#default_value' => empty($context->authorization_options['access_token_lifetime']) ? 0 : $context->authorization_options['access_token_lifetime'],
  );

  $form['authorization_options']['disable_auth_level_selection'] = array(
    '#type' => 'checkbox',
    '#title' => t('Disable authorization level selection'),
    '#description' => t('If this is checked the user won\'t be able to choose the authorization level, and the default authorization level(s) will be used.'),
    '#default_value' => !empty($context->authorization_options['disable_auth_level_selection']),
  );

  $form['authorization_levels'] = array(
    '#type' => 'fieldset',
    '#title' => t('Authorization levels'),
    '#tree' => TRUE,
    '#collapsible' => TRUE
  );

  $levels = $context->authorization_levels + array('' => array(
    'title' => '',
  ));

  foreach ($levels as $name => $level) {
    $title = !empty($name) ? check_plain($name) : t('New level');
    if ($title == '*') {
      $title = t('Full access');
    }
    $l = array(
      '#type' => 'fieldset',
      '#title' => $title,
      'name' => array(
        '#type' => 'textfield',
        '#title' => t('Name'),
        '#description' => t('The name of the authorization level.'),
        '#size' => 40,
        '#maxlength' => 255,
        '#default_value' => $name,
      ),
      'title' => array(
        '#type' => 'textfield',
        '#title' => t('Title'),
        '#description' => t('The title of the authorization level.'),
        '#size' => 40,
        '#maxlength' => 255,
        '#default_value' => $level['title'],
      ),
      'description' => array(
        '#type' => 'textarea',
        '#title' => t('Description'),
        '#description' => t('The description of the authorization level.'),
        '#default_value' => $level['description'],
      ),
      'default' => array(
        '#type' => 'checkbox',
        '#title' => t('Selected by default'),
        '#description' => t('Whether the authentication level should be checked by default.'),
        '#default_value' => is_array($context->authorization_options['default_authorization_levels']) && in_array($name, $context->authorization_options['default_authorization_levels']),
      ),
    );
    if (!empty($name)) {
      $l['delete'] = array(
        '#type' => 'checkbox',
        '#title' => t('Delete'),
        '#description' => t('Check this to delete the authorization level.'),
        '#default_value' => FALSE,
      );
    }
    $form['authorization_levels'][] = $l;
  }

  $form['submit'] = array(
    '#type'  => 'submit',
    '#value' => t('Save'),
  );

  return $form;
}

/**
 * Validate submission of the preset edit form.
 */
function oauth_common_edit_form_context_validate(&$form, &$form_state) {
  $values = $form_state['values'];

  // Test uniqueness of name:
  if (preg_match("/[^A-Za-z0-9_]/", $values['name'])) {
    form_error($form['name'], t('Context name must be alphanumeric or underscores only.'));
  }
  else {
    $query = "SELECT cid FROM {oauth_common_context} WHERE name = '%s'";
    $args  = array(
      ':name' => $values['name'],
    );
    if (!empty($values['cid']) && is_numeric($values['cid'])) {
      $query .= ' AND cid != %d';
      $args[':cid'] = $values['cid'];
    }
    if (db_result(db_query($query, $args))) {
      form_error($form['name'], t('Context name must be unique.'));
    }
  }

  // Check that the authorization level names are unique within the context
  $levels = array();
  $default_exists = FALSE;
  foreach ($values['authorization_levels'] as $idx => $level) {
    if (!empty($level['name']) && !$level['delete']) {
      if (!empty($levels[$level['name']])) {
        form_error($form['authorization_levels'][$idx]['name'], t('Authorization level name must be unique.'));
      }
      else if (preg_match("/[^A-Za-z0-9_\*]/", $level['name'])) {
        form_error($form['authorization_levels'][$idx]['name'], t('Authorization level name must be alphanumeric or underscores only.'));
      }

      if (empty($level['title'])) {
        form_error($form['authorization_levels'][$idx]['title'], t('Authorization levels must have a title.'));
      }
      $default_exists = $default_exists || $level['default'];
      $levels[$level['name']] = $level;
    }
  }

  // Check that we actually got a number as access token lifetime
  if (!is_numeric($values['authorization_options']['access_token_lifetime'])) {
    form_error($form['authorization_options']['access_token_lifetime'], t('The access token lifetime must be numeric.'));
  }

  // Check that at least one default authorization level is checked when
  // authorization level selection is disabled.
  if (!$default_exists && $values['authorization_options']['disable_auth_level_selection']) {
    form_error($form['authorization_options']['disable_auth_level_selection'], t('You must select at least one default authorirization level if level selection is disabled.'));
  }
}

/**
 * Process submission of the mini panel edit form.
 */
function oauth_common_edit_form_context_submit($form, &$form_state) {
  $context = $form_state['values']['context_object'];
  $values = $form_state['values'];

  $context->name = $values['name'];
  $context->title = $values['title'];

  $auth_options = array(
    'access_token_lifetime' => 0,
  );
  foreach ($values['authorization_options'] as $key => $value) {
    if (!empty($value)) {
      $auth_options[$key] = $value;
    }
  }
  $context->authorization_options = $auth_options;

  // Collect the names of the selected signature methods.
  $sig_options = array();
  foreach ($values['signature_methods']['selected'] as $name => $selected) {
    if ($selected) {
      $sig_options[] = $name;
    }
  }
  $context->authorization_options['signature_methods'] = $sig_options;

  // Set the auth levels and default levels for the context
  $levels = array();
  $default_levels = array();
  foreach ($values['authorization_levels'] as $level) {
    if (!empty($level['name']) && !$level['delete']) {
      $name = $level['name'];
      if ($level['default']) {
        $default_levels[] = $name;
      }
      unset($level['name'], $level['default'], $level['delete']);
      $levels[$name] = $level;
    }
  }
  $context->authorization_levels = $levels;
  $context->authorization_options['default_authorization_levels'] = $default_levels;

  oauth_common_context_save($context);

  if (empty($context->cid)) {
    drupal_set_message(t('Your new context %title has been saved.', array('%title' => $context->title)));
    $form_state['values']['cid'] = $context->cid;
  }
  else {
    drupal_set_message(t('Your changes have been saved.'));
  }

  $form_state['redirect'] = 'admin/settings/oauth';
}

/**
 * Provide a form to confirm deletion of a context.
 */
function oauth_common_delete_confirm_context(&$form_state, $context) {
  if (!is_object($context)) {
    $context = oauth_common_context_load($context);
  }
  if ($context->export_type == (EXPORT_IN_CODE | EXPORT_IN_DATABASE)) {
    $title  = t('Are you sure you want to revert the context "@title"?', array('@title' => $context->title));
    $submit = t('Revert');
  }
  elseif ($context->export_type != EXPORT_IN_CODE) {
    $title  = t('Are you sure you want to delete the context "@title"?', array('@title' => $context->title));
    $submit = t('Delete');
  }
  else {
    drupal_not_found();
    die;
  }
  $form['context'] = array('#type' => 'value', '#value' => $context->name);
  $form['cid']      = array('#type' => 'value', '#value' => $context->cid);
  return confirm_form($form,
    $title,
    !empty($_GET['destination']) ? $_GET['destination'] : 'admin/settings/oauth',
    t('This action cannot be undone.'),
    $submit, t('Cancel')
  );
}

/**
 * Handle the submit button to delete a context.
 */
function oauth_common_delete_confirm_context_submit($form, &$form_state) {
  $context = oauth_common_context_load($form_state['values']['context']);
  if ($context->cid == $form_state['values']['cid']) {
    oauth_common_context_delete($context);
    $form_state['redirect'] = 'admin/settings/oauth';
  }
}

/**
 * Page callback to export a context to PHP code.
 */
function oauth_common_export_context(&$form_state, $context) {
  if (!is_object($context)) {
    $context = oauth_common_context_load($context);
  }
  drupal_set_title(check_plain($context->title));
  $code = oauth_common_context_export($context);

  $lines = substr_count($code, "\n") + 4;
  $form['code'] = array(
    '#type'          => 'textarea',
    '#title'         => $context->title,
    '#default_value' => $code,
    '#rows'          => $lines,
  );

  return $form;
}
