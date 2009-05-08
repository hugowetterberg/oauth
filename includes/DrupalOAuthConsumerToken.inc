<?php
// $Id: DrupalOAuthConsumerToken.inc,v 1.1 2009/05/08 21:06:15 hugowetterberg Exp $

class DrupalOAuthConsumerToken extends OAuthToken {
  public $type = '';
  public $uid = 0;
  
  public function __construct($key, $secret, $params=array()) {
    parent::__construct($key, $secret);
    foreach($params as $key => $value) {
      if (isset($this->$key)) {
        $this->$key = $value;
      }
    }
  }

  /**
   * Writes the token to the database
   *
   * @param bool $update 
   *  Optional. Set to TRUE if the token exists and should be updated. Defaults to FALSE.
   * @return void
   */
  public function write($update=FALSE) {
    $primary = $update ? array('token_key') : array();
    $values = get_object_vars($this);
    $values['token_key'] = $this->key;
    drupal_write_record('oauth_common_consumer_token', $values, $primary);
  }

  /**
   * Deletes the token from the database
   *
   * @return void
   */
  public function delete() {
    self::deleteToken($this->key);
  }

  /**
   * Deletes the token with the key from the database
   *
   * @return void
   */
  public static function deleteToken($key) {
    db_query("DELETE FROM {oauth_common_consumer_token} WHERE token_key='%s'", array(
      'key' => $key,
    ));
  }

  /**
   * Gets the token with the specified key
   *
   * @param string $key
   *  The key of the token to get
   * @return DrupalOAuthConsumerToken
   *  The loaded token object or FALSE if load failed
   */
  public static function load($key) {
    return self::fromResult(db_query("SELECT * FROM {oauth_common_consumer_token} WHERE token_key='%s'", array(
      ':key' => $key,
    )));
  }

  /**
   * Constructs a token from a db-result resource
   *
   * @param resource $res
   *  A database result resource
   * @return DrupalOAuthConsumerToken
   *  The constructed token object or NULL if no rows could be read or construction failed
   */
  public static function fromResult($res) {
    if ($data = db_fetch_array($res)) {
      return new DrupalOAuthConsumerToken($data['token_key'], $data['secret'], $data);
    }
    return NULL;
  }
}