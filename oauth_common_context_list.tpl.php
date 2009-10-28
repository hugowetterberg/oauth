<?php
// $Id$
?>
<div class="contexts">
<?php foreach ($contexts as $context => $levels): ?>
  <div class="context">
    <h3><?php print $context ?></h3>
    <ul class="auth-levels">
    <?php foreach ($levels as $name => $level): ?>
      <li><?php print $level->title ?></li>
    <?php endforeach ?>
    </ul>
    <a class="edit-context" href="<?php print url('admin/settings/oauth/' . $context . '/authorizations') ?>">Edit <?php print $context ?></a>
  </div>
<?php endforeach ?>
</div>