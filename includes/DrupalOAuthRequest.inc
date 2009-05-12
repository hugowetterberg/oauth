<?php
// $Id: DrupalOAuthRequest.inc,v 1.2 2009/05/12 10:56:14 hugowetterberg Exp $

class DrupalOAuthRequest extends OAuthRequest {
  /**
   * Creates a OAuthRequest object from the current request
   *
   * @param string $http_method
   * @param string $http_url
   * @param array $parameters
   * @return OAuthRequest
   *  A OAuthRequest generated from the request
   */
  public static function from_request($http_method=NULL, $http_url=NULL, $parameters=NULL) {
    // Preparations that has to be made if we're going to detect parameters
    if ($parameters==NULL) {
      // Unset $_GET['q'] if it was created by a redirect
      if (isset($_SERVER['REDIRECT_URL'])) {
        $q = $_GET['q'];
        unset($_GET['q']);
      }
      // Check that the q parameter hasn't been created or altered by drupal
      else if(isset($_GET['q'])) {
        $q = $_GET['q'];
        $get = array();
        parse_str($_SERVER['QUERY_STRING'], $get);
        // The q parameter was in the original request, make sure it hasn't been altered
        if (isset($get['q'])) {
          $_GET['q'] = $get['q'];
        }
        // The q parameter was set by drupal, unset it
        else {
          unset($_GET['q']);
        }
      }
    }

    $req = parent::from_request($http_method, $http_url, $parameters);

    // Restore $_GET['q'] if it was touched
    if (isset($q)) {
      $_GET['q'] = $q;
    }

    return $req;
  }
}