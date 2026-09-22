<?php
/* PEAR error plumbing. Regression cover for the PHP 4 constructors, which PHP
   8 removed -- errors silently carried an empty message and code -1. */
require __DIR__ . '/bootstrap.php';
require MW_ROOT . '/phpconf/inc/pear.inc';

$e = PEAR::raiseError('boom', 42);
is_same('static: class',    get_class($e), 'PEAR_Error');
is_same('static: code',     $e->getCode(), 42);
is_same('static: message',  $e->getMessage(), 'boom');

is_true ('isError on error', PEAR::isError($e));
is_false('isError on string',PEAR::isError('not an error'));

class MwTestPear extends PEAR {
    function go() { return $this->raiseError('from instance', 7); }
}
$t  = new MwTestPear();
$e2 = $t->go();
is_same('instance: class',   get_class($e2), 'PEAR_Error');
is_same('instance: code',    $e2->getCode(), 7);
is_same('instance: message', $e2->getMessage(), 'from instance');

exit(mw_report('pear.inc'));
