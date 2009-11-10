<?php
// $Id$

/**
 * This update adds the concept of contexts for consumers and authorization levels.
 * Also adding a couple of indexes that make sense when oauth_common is
 * acting as a consumer of other services.
 */
function _oauth_common_update_6100() {
  $ret = array();

  db_add_index($ret, 'oauth_common_token', 'consumer', array('consumer_key'));

  db_add_field($ret, 'oauth_authorization_levels', 'context', array(
    'description' => t('The context for the authorization level.'),
    'type'        => 'varchar',
    'length'      => 32,
    'not null'    => TRUE,
    'default'     => 'default',
  ));

  db_add_field($ret, 'oauth_authorization_levels', 'weight', array(
    'type' => 'int',
    'not null' => TRUE,
    'default' => 0,
    'description' => 'Determines the order that the authorization levels will be displayed in.',
  ));

  db_add_field($ret, 'oauth_authorization_levels', 'enabled', array(
    'type' => 'int',
    'size' => 'tiny',
    'unsigned' => TRUE,
    'not null' => TRUE,
    'default' => 1,
    'description' => 'Whether the authorization level is enabled or disabled.',
  ));

  db_drop_primary_key($ret, 'oauth_authorization_levels');
  db_add_primary_key($ret, 'oauth_authorization_levels', array('name', 'context'));

  db_add_field($ret, 'oauth_common_consumer', 'context', array(
    'description' => t('The application context.'),
    'type'        => 'varchar',
    'length'      => 32,
    'not null'    => TRUE,
    'default'     => 'default',
  ));

  // Add the wildcard authorization level as it now is stored in
  // the database just like the other authorization levels
  oauth_common_write_authorization_level('*', 'Full access', 'This will give !appname the same permissions that you normally have and will allow it to access the full range of services that !sitename provides.', 'default', -1);

  return $ret;
}