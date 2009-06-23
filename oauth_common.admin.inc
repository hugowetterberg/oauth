<?php
// $Id: oauth_common.admin.inc,v 1.1 2009/06/23 06:55:59 hugowetterberg Exp $

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
 * Menu system callback that generates a form for
 * administrating the authorization levels.
 *
 * @return array
 *  A form array.
 */
function _oauth_common_admin_authorization() {
  $form = array();

  $levels = oauth_common_authorization_levels();
  foreach ($levels as $name => $level) {
    $set = array(
      '#type' => 'fieldset',
      '#title' => $name . ' - ' . $level->title,
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
      'delete' => array(
        '#type' => 'item',
        '#value' => l('Delete', 'admin/settings/oauth/authorization/' . $name . '/delete'),
      ),
    );
    $form[$name] = $set;
  }

  $form['add_level'] = array(
    '#type' => 'fieldset',
    '#tree' => TRUE,
    '#title' => t('Add a authorization level'),
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
  $levels = oauth_common_authorization_levels();

  // Update titles and descriptions
  foreach ($levels as $name => $level) {
    oauth_common_write_authorization_level($name, $values[$name]['title'], $values[$name]['description']);
  }

  // Add a authorization level if the name and title fields have been filled
  $add = $values['add_level'];
  if (!empty($add['name']) && !empty($add['title'])) {
    oauth_common_write_authorization_level($add['name'], $add['title'], $add['description']);
  }

  // Clear the services cache so that methods are updated
  cache_clear_all('services:', 'cache', TRUE);
}

/**
 * Menu system callback for the confirmation page when deleting a authorization
 * level.
 *
 * @param array $form_state
 * @param string $authorization
 *  The machine-readable name of the authorization level.
 * @return array
 *  A form array.
 */
function _oauth_common_admin_authorization_delete($form_state, $authorization) {
  $levels = oauth_common_authorization_levels();

  drupal_set_title(t('Deleting "!title"', array(
    '!title' => $levels[$authorization]->title,
  )));

  $form = array(
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
  $authorization = $form_state['values']['authorization'];
  $levels = oauth_common_authorization_levels();
  oauth_common_delete_authorization_level($authorization);
  drupal_set_message(t('The authorization level "!title" has been deleted', array('!title' => $levels[$authorization]->title)));
  drupal_goto('admin/settings/oauth/authorization');
}