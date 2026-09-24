<?php
/*
 * Test stub for functions.inc.
 *
 * The real functions.inc is the aggregator: it requires every other .inc in
 * the tree, and config.inc's boot-time discovery then tries to find and mount
 * a configuration partition. On a build host that ends the process.
 *
 * A unit test loads the ONE file it is testing plus the leaf helpers it needs
 * (xmlparse.inc, util.inc) and stubs whatever else that file calls. Putting
 * tests/stubs on the include_path makes a bare require_once("functions.inc")
 * -- which shaper.inc and the captive portal files do -- resolve here instead,
 * because PHP searches the include_path before the calling file's directory.
 *
 * Deliberately empty: anything a test actually needs is declared in the test.
 */
