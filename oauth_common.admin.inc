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
        'href'  => 'admin/settings/oauth/contexts/' . $context->name . '/edit',
      );
      $operations[] = array(
        'title' => t('Export'),
        'href'  => 'admin/settings/oauth/contexts/' . $context->name . '/export',
      );
    }

    if ($context->export_type == (EXPORT_IN_CODE | EXPORT_IN_DATABASE)) {
      $operations[] = array(
        'title' => t('Revert'),
        'href'  => 'admin/settings/oauth/contexts/' . $context->name . '/delete',
      );
    }
    elseif ($context->export_type != EXPORT_IN_CODE) {
      $operations[] = array(
        'title' => t('Delete'),
        'href'  => 'admin/settings/oauth/contexts/' . $context->name . '/delete',
      );
    }
    elseif (empty($context->disabled)) {
      $operations[] = array(
        'title' => t('Disable'),
        'href'  => 'admin/settings/oauth/contexts/' . $context->name . '/disable',
        'query' => drupal_get_destination(),
      );
    }
    else {
      $operations[] = array(
        'title' => t('Enable'),
        'href'  => 'admin/settings/oauth/contexts/' . $context->name . '/enable',
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

  $table = theme('table', $header, $rows, array('id' => 'services-list-contexts'));

  drupal_add_css(drupal_get_path('module', 'services') . '/css/services.admin.css');

  return $table;
}

function _oauth_common_admin_contexts() {
  $contexts = oauth_common_authorization_contexts();
  return theme('oauth_common_context_list', $contexts);
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