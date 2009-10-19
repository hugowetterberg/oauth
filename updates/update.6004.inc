<?php
// $Id$

/**
 * This update adds the concept of contexts for consumers and authorization levels.
 */
function _oauth_common_update_6004() {
  $ret = array();

  db_add_field($ret, 'oauth_authorization_levels', 'context', array(
    'description' => t('The context for the authorization level.'),
    'type'        => 'varchar',
    'length'      => 32,
    'not null'    => TRUE,
    'default'     => '',
  ));

  db_add_field($ret, 'oauth_common_consumer', 'context', array(
    'description' => t('The application context.'),
    'type'        => 'varchar',
    'length'      => 32,
    'not null'    => TRUE,
    'default'     => '',
  ));

  return $ret;
}