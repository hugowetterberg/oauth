<?php
// $Id$

/**
 * This update turns the contexts into ctools-manageable entities and migrates
 * the authorization levels into the new contexts table.
 */
function _oauth_common_update_6101() {
  $ret = array();

  $contexts = array();

  db_create_table($ret, 'oauth_common_context', _oauth_common_oauth_common_context_6101());

  $res = db_query("SELECT * FROM {oauth_authorization_levels}");
  while ($l = db_fetch_array($res)) {
    $contexts[$l['context']] = $l;
  }

  // Set name and title for the contexts properly
  foreach ($contexts as $name => $context) {
    $contexts[$name]['name'] = $name;
    $contexts[$name]['title'] = $name;
  }

  db_drop_table($ret, 'oauth_authorization_levels');

  return $ret;
}

function _oauth_common_oauth_common_context_6101() {
  return array(
    'description' => 'Stores contexts for OAuth common',
    'export' => array(
      'identifier'      => 'context',
      'export callback' => 'oauth_common_context_export',
      'list callback'   => 'oauth_common_context_list',
      'key'             => 'name',
    ),
    'fields' => array(
      'cid' => array(
        'type'        => 'serial',
        'description' => 'Primary ID field for the table. Not used for anything except internal lookups.',
        'not null'    => TRUE,
        'no export'   => TRUE,
      ),
      'name' => array(
        'description' => 'The computer-readable name of the context.',
        'type'        => 'varchar',
        'length'      => 32,
        'not null'    => TRUE,
      ),
      'title' => array(
        'description' => 'The localizable title of the authorization context.',
        'type'        => 'varchar',
        'length'      => 100,
        'not null'    => TRUE,
      ),
      'authorization_options' => array(
        'description'    => 'Authorization options.',
        'type'           => 'text',
        'size'           => 'big',
        'not null'       => TRUE,
        'serialize'      => TRUE,
        'object default' => array(),
      ),
      'authorization_levels' => array(
        'description'    => 'Authorization levels for the context.',
        'type'           => 'text',
        'size'           => 'big',
        'not null'       => TRUE,
        'serialize'      => TRUE,
        'object default' => array(),
      ),
    ),
    'primary key' => array('cid'),
    'unique keys' => array(
      'context' => array('name'),
    ),
  );
}