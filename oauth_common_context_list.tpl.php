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
    <?php
      print l(t('Edit @context', array(
          '@context' => $context,
        )),
        'admin/settings/oauth/' . $context . '/authorizations',
        array(
          'attributes' => array(
            'class' => 'edit-context',
          ),
        ));
    ?>
  </div>
<?php endforeach ?>
</div>