<?php

function oauth_common_consumerui_list_consumers() {
  module_load_include('consumers.inc', 'oauth_common');
  return oauth_common_page_user_consumers((object)array('uid' => 0), FALSE);
}
