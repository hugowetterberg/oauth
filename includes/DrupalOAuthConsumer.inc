<?php
// $Id: DrupalOAuthConsumer.inc,v 1.1 2010/05/20 16:16:05 hugowetterberg Exp $

class DrupalOAuthConsumer extends OAuthConsumer {
  public $uid = 0;
  public $provider_consumer = TRUE;
  public $name = '';
  public $context = '';
  public $created = 0;
  public $changed = 0;
  public $callback_url = 'oob';
  public $configuration = array();
  public $in_database = FALSE;

  function __construct($key, $secret, $callback_url='oob', $provider_consumer=TRUE, $params=array()) {
    parent::__construct($key, $secret, $callback_url);
    $this->provider_consumer = $provider_consumer;
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
    $primary = $update ? array('consumer_key', 'provider_consumer') : array();

    if (!$update) {
      $this->created = time();
    }
    $this->changed = time();

    $values = get_object_vars($this);
    $values['consumer_key'] = $this->key;

    if (empty($values['configuration'])) {
      $values['configuration'] = array();
    }
    $values['configuration'] = serialize($values['configuration']);

    // Stop the created time from being modified
    if ($update) {
      unset($values['created']);
    }

    drupal_write_record('oauth_common_consumer', $values, $primary);
    $this->in_database = TRUE;
  }

  /**
   * Deletes the consumer from the database
   *
   * @return void
   */
  public function delete() {
    self::deleteConsumer($this->key, $this->provider_consumer);
  }

  /**
   * Deletes the consumer with the key from the database.
   *
   * @param string $key
   *  The consumer key.
   * @param bool $provider_consumer
   *  Optional. Whether the consumer we're about to delete is a provider or
   *  consumer consumer. Defaults to TRUE.
   * @return void
   */
  public static function deleteConsumer($key, $provider_consumer=TRUE) {
    db_query("DELETE FROM {oauth_common_consumer} 
      WHERE consumer_key='%s'
      AND provider_consumer=%d", array(
        ':consumer_key' => $key,
        ':provider_consumer' => $provider_consumer,
    ));
  }

  /**
   * Gets the consumer with the specified key
   *
   * @param string $key
   *  The key of the consumer to get
   * @param bool $provider_consumer
   *  Optional. Whether the consumer we're about to load is a provider or
   *  consumer consumer. Defaults to TRUE.
   * @return DrupalOAuthConsumer
   *  The loaded consumer object or FALSE if load failed
   */
  public static function load($key, $provider_consumer=TRUE) {
    return self::fromResult(db_query("SELECT * FROM {oauth_common_consumer} 
      WHERE consumer_key='%s' AND provider_consumer='%d'", array(
        ':consumer_key' => $key,
        ':provider_consumer' => $provider_consumer,
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
      if (!empty($data['configuration'])) {
        $data['configuration'] = unserialize($data['configuration']);
      }
      $data['in_database'] = TRUE;
      return new DrupalOAuthConsumer($data['consumer_key'], $data['secret'], $data['callback_url'], $data['provider_consumer'], $data);
    }
    return NULL;
  }
}