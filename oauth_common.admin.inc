<?php
// $Id: oauth_common.admin.inc,v 1.2 2010/01/19 10:43:58 hugowetterberg Exp $

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