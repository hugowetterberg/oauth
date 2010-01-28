<?php
// $Id$

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

  $form['authorization_options'] = array(
    '#type' => 'fieldset',
    '#title' => t('Authorization options'),
    '#tree' => TRUE,
  );

  $sign_methods = array(
    'PLAINTEXT' => t('Plaintext'),
    'PLAINTEXT-SSL' => t('Plaintext (if https)'),
  );
  foreach (hash_algos() as $algo) {
    $sign_methods['HMAC-' . strtoupper($algo)] = 'HMAC-' . strtoupper($algo);
  }

  $form['authorization_options']['signature_methods'] = array(
    '#type' => 'fieldset',
    '#title' => t('Signature methods'),
    '#collapsible' => TRUE,
    '#collapsed' => TRUE,
    'selected' => array(
      '#type' => 'checkboxes',
      '#title' => t('Supported signature methods'),
      '#options' => $sign_methods,
      '#default_value' => !empty($context->authorization_options['signature_methods']) ?
         $context->authorization_options['signature_methods']:
         array('PLAINTEXT-SSL', 'HMAC-SHA1', 'HMAC-SHA256', 'HMAC-SHA384', 'HMAC-SHA512', 'HMAC-CRC32'),
    )
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

  $form['authorization_options']['warning'] = array(
    '#type' => 'textarea',
    '#title' => t('Warning'),
    '#description' => t('The warning shown to the user when authorizing.'),
    '#default_value' => $context->authorization_options['warning'],
  );

  $form['authorization_levels'] = array(
    '#type' => 'fieldset',
    '#title' => t('Authorization levels'),
    '#tree' => TRUE,
  );

  foreach ($context->authorization_levels as $name => $level) {
    $form['authorization_levels'][] = array(
      '#type' => 'fieldset',
      '#title' => t('Level'),
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
      'default' => array(
        '#type' => 'textfield',
        '#title' => t('Selected by default'),
        '#description' => t('Whether the authentication level should be checked by default.'),
        '#size' => 40,
        '#maxlength' => 255,
        '#default_value' => $level['title'],
      ),
    );
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
function oauth_common_edit_form_context_validate($form, &$form_state) {
  // Test uniqueness of name:
  if (preg_match("/[^A-Za-z0-9_]/", $form_state['values']['context'])) {
    form_error($form['name'], t('Endpoint name must be alphanumeric or underscores only.'));
  }
  else {
    $query = "SELECT cid FROM {oauth_common_context} WHERE name = '%s'";
    $args  = array($form_state['values']['context']);
    if (!empty($form_state['values']['cid']) && is_numeric($form_state['values']['cid'])) {
      $query .= ' AND cid != %d';
      $args[] = $form_state['values']['cid'];
    }
    if (db_result(db_query($query, $args))) {
      form_error($form['name'], t('Context name must be unique.'));
    }
  }
}

/**
 * Process submission of the mini panel edit form.
 */
function oauth_common_edit_form_context_submit($form, &$form_state) {
  $context = $form_state['values']['context_object'];

  $context->name = $form_state['values']['name'];
  $context->title = $form_state['values']['title'];

  if (empty($context->cid)) {
    drupal_set_message(t('Your new context %title has been saved.', array('%title' => $context->title)));
    oauth_common_context_save($context);
    $form_state['values']['cid'] = $context->cid;
  }
  else {
    drupal_set_message(t('Your changes have been saved.'));
    oauth_common_context_save($context);
  }

  $form_state['redirect'] = 'admin/build/oauth_common/list';
}

/**
 * Menu system callback that generates a form for
 * administrating the authorization levels.
 *
 * @param string $context
 *  The context whose authorization levels should be administered.
 *
 * @return array
 *  A form array.
 */
function _oauth_common_admin_authorization($form_state, $context='default') {
  $form = array();

  $form['context'] = array(
    '#type' => 'value',
    '#value' => $context,
  );

  $levels = oauth_common_authorization_levels($context);
  foreach ($levels as $name => $level) {
    $set = array(
      '#type' => 'fieldset',
      '#title' => '"' . $name . '" - ' . $level->title,
      '#tree' => TRUE,
      'title' => array(
        '#type' => 'textfield',
        '#maxlength' => 100,
        '#title' => t('Title'),
        '#default_value' => $level->title,
      ),
      'description' => array(
        '#type' => 'textarea',
        '#maxlength' => 255,
        '#title' => t('Description'),
        '#default_value' => $level->description,
      ),
      'weight' => array(
        '#type' => 'textfield',
        '#maxlength' => 3,
        '#title' => t('Weight'),
        '#default_value' => $level->weight,
      ),
      'enabled' => array(
        '#type' => 'checkbox',
        '#title' => t('Enabled'),
        '#default_value' => $level->enabled,
      ),
      'delete' => array(
        '#type' => 'item',
        '#value' => l('Delete', 'admin/settings/oauth/' . $context . '/authorizations/' . $name . '/delete'),
      ),
    );
    $form[$name] = $set;
  }

  $form['add_level'] = array(
    '#type' => 'fieldset',
    '#tree' => TRUE,
    '#title' => t('Add a authorization level'),
    '#collapsible' => TRUE,
    '#collapsed' => TRUE,
    'name' => array(
      '#type' => 'textfield',
      '#maxlength' => 32,
      '#title' => t('Name'),
      '#default_value' => '',
    ),
    'title' => array(
      '#type' => 'textfield',
      '#maxlength' => 100,
      '#title' => t('Title'),
      '#default_value' => '',
    ),
    'description' => array(
      '#type' => 'textarea',
      '#maxlength' => 255,
      '#title' => t('Description'),
      '#default_value' => '',
    ),
  );

  $form['submit'] = array(
    '#type' => 'submit',
    '#value' => t('Save'),
  );

  return $form;
}

function _oauth_common_admin_authorization_submit($form, $form_state) {
  $values = $form_state['values'];
  $context = $values['context'];
  $levels = oauth_common_authorization_levels($context);

  // Update titles and descriptions
  foreach ($levels as $name => $level) {
    $lv = $values[$name];
    $lv['weight'] = intval($lv['weight']);
    oauth_common_write_authorization_level($name, $lv['title'], $lv['description'], $context, $lv['weight'], $lv['enabled']);
  }

  // Add a authorization level if the name and title fields have been filled
  $add = $values['add_level'];
  if (!empty($add['name']) && !empty($add['title'])) {
    oauth_common_write_authorization_level($add['name'], $add['title'], $add['description'], $context);
  }

  // TODO: This doesn't belong here, we need a hook that services_oauth could respond to
  // Clear the services cache so that methods are updated
  cache_clear_all('services:', 'cache', TRUE);
}

/**
 * Menu system callback for the confirmation page when deleting a authorization
 * level.
 *
 * @param array $form_state
 * @param string $context
 *  The context of the authorization to delete.
 * @param string $authorization
 *  The machine-readable name of the authorization level.
 * @return array
 *  A form array.
 */
function _oauth_common_admin_authorization_delete($form_state, $context, $authorization) {
  $levels = oauth_common_authorization_levels($context);

  drupal_set_title(t('Deleting "!title"', array(
    '!title' => $levels[$authorization]->title,
  )));

  $form = array(
    'context' => array(
      '#type' => 'value',
      '#value' => $context,
    ),
    'authorization' => array(
      '#type' => 'value',
      '#value' => $authorization,
    ),
  );

  $form['description'] = array(
    '#type' => 'item',
    '#value' => t('Are you sure that you want to delete the authorization level "!title" (!name). Operations that have been set to require this authorization level will be set to require full access. This could be a <em>very bad thing</em> on a production site, and <em>will</em> break applications that integrate with your site (if they have been granted this authorization level and depend on it). Only do this if you <em>really</em> know what you\'re doing.', array(
      '!title' => $levels[$authorization]->title,
      '!name' => $authorization,
    )),
  );

  $form['confirm'] = array(
    '#type' => 'checkbox',
    '#title' => t('I\'ve really read and understood the above warning. Delete the authorization level please!'),
    '#required' => TRUE,
  );

  $form['submit'] = array(
    '#type' => 'submit',
    '#value' => t('Delete'),
  );

  return $form;
}

function _oauth_common_admin_authorization_delete_submit($form, $form_state) {
  $context = $form_state['values']['context'];
  $authorization = $form_state['values']['authorization'];

  // Load the authorization level before we delete is so that
  // we can use it to display the title in our status message.
  $levels = oauth_common_authorization_levels($context);
  oauth_common_delete_authorization_level($authorization, $context);
  drupal_set_message(t('The authorization level "!title" has been deleted', array('!title' => $levels[$authorization]->title)));
  drupal_goto('admin/settings/oauth/authorizations/' . $context);
}