<?php
// $Id: DrupalOAuthConsumer.inc,v 1.1 2009/05/08 21:06:15 hugowetterberg Exp $

class DrupalOAuthConsumer extends OAuthConsumer {
  public $uid = 0;
  public $name = '';
  public $created = 0;
  public $changed = 0;
  public $type = '';
  public $callback_url = NULL;

  function __construct($key, $secret, $callback_url=NULL, $params=array()) {
    parent::__construct($key, $secret, $callback_url);
    foreach($params as $key => $value) {
      if (isset($this->$key)) {
        $this->$key = $value;
      }
    }
  }
  
  /**
   * Writes the consumer to the database
   *
   * @param bool $update 
   *  Optional. Set to TRUE if the consumer exists and should be updated. Defaults to FALSE.
   * @return void
   */
  public function write($update=FALSE) {
    $primary = $update ? array('consumer_key') : array();

    if (!$update) {
      $this->created = time();
    }
    $this->changed = time();

    $values = get_object_vars($this);
    $values['consumer_key'] = $this->key;

    // Stop the created time from being modified
    if ($update) {
      unset($values['created']);
    }

    drupal_write_record('oauth_common_consumer', $values, $primary);
  }

  /**
   * Deletes the consumer from the database
   *
   * @return void
   */
  public function delete() {
    self::deleteConsumer($this->key);
  }

  /**
   * Deletes the consumer with the key from the database
   *
   * @return void
   */
  public static function deleteConsumer($key) {
    db_query("DELETE FROM {oauth_common_consumer} WHERE consumer_key='%s'", array(
      'key' => $key,
    ));
  }

  /**
   * Gets the consumer with the specified key
   *
   * @param string $key
   *  The key of the consumer to get
   * @return DrupalOAuthConsumer
   *  The loaded consumer object or FALSE if load failed
   */
  public static function load($key) {
    return self::fromResult(db_query("SELECT * FROM {oauth_common_consumer} WHERE consumer_key='%s'", array(
      ':key' => $key,
    )));
  }

  /**
   * Constructs a consumer from a db-result resource
   *
   * @param resource $res
   *  A database result resource
   * @return DrupalOAuthConsumer
   *  The constructed consumer object or NULL if no rows could be read or construction failed
   */
  public static function fromResult($res) {
    if ($data = db_fetch_array($res)) {
      return new DrupalOAuthConsumer($data['consumer_key'], $data['secret'],  $data['callback_url'], $data);
    }
    return NULL;
  }
}