<?php
// $Id: OAuthCommonHooks.inc,v 1.1 2009/06/23 06:55:59 hugowetterberg Exp $

/**
 * Class used to collect hook implementations that doesn't need to be included
 * on every page load.
 */
class OAuthCommonHooks {

  public static function cron() {
    db_query("DELETE FROM {oauth_common_token}
      WHERE expires!=0
      AND expires <= %d", array(
        ':now' => time(),
    ));
  }

  /**
   * Implementation of hook_user().
   */
  public static function user($op, &$edit, &$account, $category = NULL) {
    global $user;

    if ($op == 'delete') {
      // Delete all tokens and consumers related to a user
      module_load_include('inc', 'oauth_common');
      $consumers = _oauth_common_user_consumer_info($account->uid);
      db_query('DELETE FROM {oauth_common_consumer}
        WHERE uid = %d', array(
          ':uid' => $account->uid,
        ));
      db_query("DELETE FROM {oauth_common_token}
        WHERE uid = %d OR consumer_key = '%s'", array(
          ':uid' => $account->uid,
          ':consumer_key' => $consumer->consumer_key,
        ));
    }
  }

  /**
   * Implementation of hook_menu().
   */
  public static function menu() {
    $menu = array();

    $menu['admin/settings/oauth'] = array(
      'title' => 'OAuth',
      'description' => 'Settings for OAuth',
      'page callback' => 'drupal_get_form',
      'page arguments' => array('_oauth_common_admin'),
      'access arguments' => array('administer oauth'),
      'file' => 'oauth_common.admin.inc',
      'type' => MENU_NORMAL_ITEM,
    );
    $menu['admin/settings/oauth/general'] = array_merge($menu['admin/settings/oauth'], array(
      'title' => 'Settings',
      'type' => MENU_DEFAULT_LOCAL_TASK,
      'weight' => -10,
    ));

    $menu['admin/settings/oauth/authorizations'] = array(
      'title' => 'Authorization levels',
      'page callback' => 'drupal_get_form',
      'page arguments' => array('_oauth_common_admin_authorization'),
      'access arguments' => array('administer oauth'),
      'file' => 'oauth_common.admin.inc',
      'type' => MENU_LOCAL_TASK,
    );

    $menu['admin/settings/oauth/authorization/%/delete'] = array(
      'title' => 'Delete authorization level',
      'page callback' => 'drupal_get_form',
      'page arguments' => array('_oauth_common_admin_authorization_delete', 4),
      'access arguments' => array('administer oauth'),
      'file' => 'oauth_common.admin.inc',
      'type' => MENU_CALLBACK,
    );

    $menu['oauth/authorize'] = array(
      'page callback' => 'drupal_get_form',
      'page arguments' => array('_oauth_common_authorize'),
      'access callback' => '_oauth_common_always_true',
      'file' => 'oauth_common.pages.inc',
      'type' => MENU_CALLBACK,
    );

    $menu['oauth/authorized'] = array(
      'title' => 'Authorization finished',
      'page callback' => '_oauth_common_authorized',
      'access callback' => '_oauth_common_always_true',
      'file' => 'oauth_common.pages.inc',
      'type' => MENU_CALLBACK,
    );

    $menu['oauth/request_token'] = array(
      'page callback' => '_oauth_common_request_token',
      'access callback' => '_oauth_common_always_true',
      'file' => 'oauth_common.pages.inc',
      'type' => MENU_CALLBACK,
    );

    $menu['oauth/access_token'] = array(
      'page callback' => '_oauth_common_access_token',
      'access callback' => '_oauth_common_always_true',
      'file' => 'oauth_common.pages.inc',
      'type' => MENU_CALLBACK,
    );

    $menu['user/%user/applications'] = array(
      'title' => 'Applications',
      'page callback' => 'drupal_get_form',
      'page arguments' => array('_oauth_common_user_applications', 1),
      'access callback' => '_oauth_common_user_access',
      'access arguments' => array(1, 'oauth authorize consumers'),
      'file' => 'oauth_common.pages.inc',
      'type' => MENU_LOCAL_TASK,
    );

    $menu['user/%user/applications/add'] = array(
      'title' => 'Add application',
      'page callback' => 'drupal_get_form',
      'page arguments' => array('_oauth_common_user_applications_add', 1),
      'access callback' => '_oauth_common_user_access',
      'access arguments' => array(1, 'oauth register consumers'),
      'file' => 'oauth_common.pages.inc',
      'type' => MENU_CALLBACK,
    );

    $menu['user/%user/applications/authorization/%'] = array(
      'title' => 'Edit authorization',
      'page callback' => 'drupal_get_form',
      'page arguments' => array('_oauth_common_user_authorization_edit', 1, 4),
      'access callback' => '_oauth_common_user_access',
      'access arguments' => array(1, 'oauth authorize consumers'),
      'file' => 'oauth_common.pages.inc',
      'type' => MENU_CALLBACK,
    );

    $menu['user/%user/applications/authorization/%/delete'] = array(
      'title' => 'Delete authorization',
      'page callback' => 'drupal_get_form',
      'page arguments' => array('_oauth_common_user_authorization_delete', 1, 4),
      // We always want to allow the user to delete a authorization, that
      // shouldn't be a permission that can be rescinded.
      'access callback' => 'user_edit_access',
      'access arguments' => array(1),
      'file' => 'oauth_common.pages.inc',
      'type' => MENU_CALLBACK,
    );

    $menu['oauth/test/valid-consumer'] = array(
      'file' => 'oauth_common.pages.inc',
      'page callback' => '_oauth_common_validate_request_callback',
      'page arguments' => array('consumer'),
      'access arguments' => array('access content'),
      'type' => MENU_CALLBACK,
    );

    $menu['oauth/test/valid-access-token'] = array(
      'file' => 'oauth_common.pages.inc',
      'page callback' => '_oauth_common_validate_request_callback',
      'page arguments' => array('access token'),
      'access arguments' => array('access content'),
      'type' => MENU_CALLBACK,
    );

    return $menu;
  }

  /**
   * Implementation of hook_xrds().
   */
  public static function xrds() {
    $xrds = array();
    $xrds['oauth'] = array(
      'services' => array(
        array(
          'data' => array(
            'Type' => array('http://oauth.net/discovery/1.0'),
            'URI' => array('#main'),
          ),
        ),
        array(
          'data' => array(
            'Type' => array(
              'http://oauth.net/core/1.0/endpoint/request',
              'http://oauth.net/core/1.0/parameters/auth-header',
              'http://oauth.net/core/1.0/parameters/uri-query',
              'http://oauth.net/core/1.0/signature/HMAC-SHA1',
            ),
            'URI' => array(url('oauth/request_token', array('absolute'=>TRUE))),
          ),
        ),
        array(
          'data' => array(
            'Type' => array(
              'http://oauth.net/core/1.0/endpoint/authorize',
              'http://oauth.net/core/1.0/parameters/uri-query',
            ),
            'URI' => array(url('oauth/authorize', array('absolute'=>TRUE))),
          ),
        ),
        array(
          'data' => array(
            'Type' => array(
              'http://oauth.net/core/1.0/endpoint/access',
              'http://oauth.net/core/1.0/parameters/auth-header',
              'http://oauth.net/core/1.0/parameters/uri-query',
              'http://oauth.net/core/1.0/signature/HMAC-SHA1',
            ),
            'URI' => array(url('oauth/access_token', array('absolute'=>TRUE))),
          ),
        ),
      ),
    );
    return $xrds;
  }
}