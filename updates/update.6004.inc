<?php
// $Id$

/**
 * This update adds context information to the oauth_authorization_levels and oauth_common_consumer tables.
 */
function _oauth_common_update_6004() {
  $ret = array();

  db_add_field($ret, 'oauth_common_consumer', 'context', array(
    'description' => t('The context that the consumer is valid within.'),
    'type'        => 'varchar',
    'length'      => 64,
    'not null'    => TRUE,
    'default'     => '',
  ));
  db_add_index($ret, 'oauth_common_consumer', 'context', array('context'));

  db_add_field($ret, 'oauth_common_authorization_levels', 'context', array(
    'description' => t('The context that the authorization level is valid within.'),
    'type'        => 'varchar',
    'length'      => 64,
    'not null'    => TRUE,
    'default'     => '',
  ));
  db_drop_primary_key('oauth_common_authorization_levels');
  db_add_primary_key('oauth_common_authorization_levels', array('name', 'context'));

  return $ret;
}