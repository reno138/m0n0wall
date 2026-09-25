#!/usr/local/bin/php
<?php 
/*
	$Id$
	Copyright (C) 2007 Marcel Wiget <mwiget@mac.com>
	All rights reserved. 
	
	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:
	
	1. Redistributions of source code must retain the above copyright notice,
	   this list of conditions and the following disclaimer.
	
	2. Redistributions in binary form must reproduce the above copyright
	   notice, this list of conditions and the following disclaimer in the
	   documentation and/or other materials provided with the distribution.
	
	THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
	INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
	AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
	AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
	OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/
$pgtitle = array("Services", "Captive portal", "Vouchers");
require("guiconfig.inc");

if (!is_array($config['voucher'] ?? null)) {
    $config['voucher'] = array();
}

if (!is_array($config['voucher']['roll'] ?? null)) {
    $config['voucher']['roll'] = array();
}
if (!isset($config['voucher']['charset'])) {
    $config['voucher']['charset'] = '2345678abcdefhijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';
}
if (!isset($config['voucher']['rollbits'])) {
    $config['voucher']['rollbits'] = 16;
}
if (!isset($config['voucher']['ticketbits'])) {
    $config['voucher']['ticketbits'] = 10;
}
if (!isset($config['voucher']['saveinterval'])) {
    $config['voucher']['saveinterval'] = 300;
}
if (!isset($config['voucher']['checksumbits'])) {
    $config['voucher']['checksumbits'] = 5;
}
if (!isset($config['voucher']['magic'])) {
    /* random_int(), not rand(): rand() is a Mersenne Twister capped at 2^31-1,
       so two of the magic field's 33 bits would always be zero and the value
       would be predictable from any other rand() output in the same request.
       Kept as a decimal STRING because voucher.cfg parses it with %llu. */
    $config['voucher']['magic'] = (string) random_int(0, PHP_INT_MAX);
}

/* The voucher secret: one 256-bit key that both prints and validates vouchers.
   It replaces $config['voucher']['publickey'] / ['privatekey'] outright.
   The RSA pair could not even be generated under OpenSSL 3 -- "voucher -g 64"
   failed with "key size too small" -- so the feature has never worked on this
   platform and there is nothing in the field to preserve. See
   build/tools/voucher.c for the full reasoning.

   Persisted IMMEDIATELY with write_config(). The CSV link in the roll list
   below is a GET that prints a roll, so an admin who clicks it before pressing
   Save would otherwise get vouchers printed under a secret that the next page
   load regenerates -- silently orphaning every voucher just printed. */
$keygen_error = "";
if (empty($config['voucher']['fpekey'])) {
    if (voucher_new_key()) {
        $had_rsa = isset($config['voucher']['publickey']) ||
                   isset($config['voucher']['privatekey']);
        unset($config['voucher']['publickey']);
        unset($config['voucher']['privatekey']);
        write_config();
        voucher_log(LOG_NOTICE, $had_rsa
            ? "generated a new voucher secret and discarded the unusable RSA " .
              "voucher key pair from the configuration"
            : "generated a new voucher secret");
    } else {
        $keygen_error = "Could not generate a voucher secret. " .
            "Is /usr/local/bin/voucher installed and working?";
    }
}
if (!isset($config['voucher']['msgnoaccess'])) {
    $config['voucher']['msgnoaccess'] = "Voucher invalid";
}
if (!isset($config['voucher']['msgexpired'])) {
    $config['voucher']['msgexpired'] = "Voucher expired";
}

/* Guaranteed to be an array before the reference is taken. A firewall with no
   voucher rolls yet -- which is every firewall until the admin adds one -- has no
   'roll' section at all, so the foreach that renders the table below was handed
   null and warned on every view of the page. */
if (!isset($config['voucher']['roll']) || !is_array($config['voucher']['roll']))
    $config['voucher']['roll'] = array();
$a_roll = &$config['voucher']['roll'];

if ($_POST) {
	foreach ($_POST as $pn => $pv) {
		if (preg_match("/^del_(\d+)_x$/", $pn, $matches)) {
			$id = $matches[1];
			if (!empty($a_roll[$id])) {
		        $roll = $a_roll[$id]['number']; 
		        voucher_lock();
		        unset($a_roll[$id]);
		        voucher_unlink_db($roll);
		        voucher_unlock();
		        write_config();
		        header("Location: services_captiveportal_vouchers.php");
		        exit;
		    }
		}
	}
}

/* print all vouchers of the selected roll */
if (($_GET['act'] ?? null) == "csv") {
    if (empty($config['voucher']['fpekey'])) {
        $input_errors[] = "No voucher secret configured yet. Save this page first.\n";
    } else if (voucher_write_keyfile() != 0) {
        $input_errors[] = "Cannot write the voucher key file.\n";
    } else if (voucher_write_cfgfile() != 0) {
        $input_errors[] = "Cannot write the voucher config file.\n";
    } else {
        $a_voucher = &$config['voucher']['roll'];
        $id = $_GET['id'] ?? null;
        if (isset($id) && !empty($a_voucher[$id])) {
            /* (int): these are numeric by definition and they reach a shell */
            $number = (int)($a_voucher[$id]['number'] ?? 0);
            $count = (int)($a_voucher[$id]['count'] ?? 0);

            header("Content-Type: application/octet-stream");
            header("Content-Disposition: attachment; filename=vouchers_roll$number.csv");
            system(VOUCHER_BIN . " -c {$g['varetc_path']}/voucher.cfg -K {$g['varetc_path']}/voucher.key -p $number $count");
            /* DO NOT unlink the key here.
               The RSA version wrote voucher.private, printed, then unlinked it,
               because a gateway that only validates needed nothing but the
               public key. One secret now does both jobs, so deleting the file
               after a print destroys the key the captive portal needs to
               validate -- logins would then fail for every guest, and only
               after an admin printed a roll. tests/t_voucher.php validates a
               voucher AFTER a print so this cannot be "tidied" back in. */
            exit;
        }
    }
}

$pconfig['enable'] = isset($config['voucher']['enable']);
$pconfig['charset'] = $config['voucher']['charset'] ?? null;
$pconfig['rollbits'] = $config['voucher']['rollbits'] ?? null;
$pconfig['ticketbits'] = $config['voucher']['ticketbits'] ?? null;
$pconfig['saveinterval'] = $config['voucher']['saveinterval'] ?? null;
$pconfig['checksumbits'] = $config['voucher']['checksumbits'] ?? null;
$pconfig['magic'] = $config['voucher']['magic'] ?? null;
/* The secret itself is never shown or accepted through the form: both printing
   and validating are local, so there is nothing to paste in and nothing to
   copy out. A fingerprint is enough for an admin to see whether it changed. */
/* A helper, not an inline expression, for two reasons: the value has to be
   re-derived after $pconfig is replaced by $_POST on a POST, and a secret that
   fails to decode must NOT render as a healthy-looking fingerprint.
   
   The inline version passed `base64_decode(..., true) ?: ''` to hash(), so a
   corrupted or truncated secret displayed the SHA-256 of the empty string
   (e3b0c44298fc1c14) on the one page whose job is to show whether the key is
   good -- while voucher_write_keyfile() was separately refusing that same value
   as malformed. */
function voucher_key_fingerprint() {
    global $config;

    if (empty($config['voucher']['fpekey']))
        return '';
    $raw = base64_decode($config['voucher']['fpekey'], true);
    if ($raw === false || strlen($raw) != 32)
        return false;           /* present but unusable -- distinct from absent */
    return substr(hash('sha256', $raw), 0, 16);
}

$pconfig['keyfp'] = voucher_key_fingerprint();
$pconfig['msgnoaccess'] = $config['voucher']['msgnoaccess'] ?? null;
$pconfig['msgexpired'] = $config['voucher']['msgexpired'] ?? null;

if ($_POST) {

	unset($input_errors);
	$pconfig = $_POST;
	/* keyfp is not a form field, so replacing $pconfig wholesale above loses it.
	   Without this the page reported "not yet generated" after EVERY Save, with a
	   perfectly good secret sitting in config.xml, plus an undefined-key warning
	   into the system log. */
	$pconfig['keyfp'] = voucher_key_fingerprint();

	/* input validation */
	if (!empty($_POST['enable'])) {
		$reqdfields = explode(" ", "charset rollbits ticketbits checksumbits magic saveinterval");
		$reqdfieldsn = explode(",", "charset,rollbits,ticketbits,checksumbits,magic,saveinterval");
		
		do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
	}
	
	if (!empty($_POST['charset']) && (strlen($_POST['charset']) < 2)) {	/* the ) was inside strlen() */
		$input_errors[] = "Need at least 2 characters to create vouchers.";
	}
	/* strpos() !== false, not > 0: a charset that STARTS with the forbidden
	   character gave offset 0, which "> 0" accepts. A leading comma puts a
	   sixth field in voucher.cfg and the tool's five-field fscanf then
	   mis-parses the line. A space is newly rejected as well: the tool's
	   code_parse() treats a space as the end of the code (the CSV prints each
	   code as " %s"), so a space in the charset would silently truncate every
	   voucher at that character. */
	$badchars = array('"' => "Double quotes", ',' => "Commas");
	foreach ($badchars as $bc => $bcname) {
		if (!empty($_POST['charset']) && (strpos($_POST['charset'], $bc) !== false)) {
			$input_errors[] = "$bcname aren't allowed in the character set.";
		}
	}
	if (!empty($_POST['charset'])) {
		/* ANY whitespace, not just a space.
		
		   The tool reads the charset with "%255s" in its five-field fscanf, and
		   %s ends the field at any whitespace byte -- so a tab or a newline
		   truncates the alphabet to whatever precedes it just as a space does,
		   while this page goes on displaying the whole thing. Tab, CR and LF get
		   through do_input_validation()'s control-character check, which
		   deliberately permits them. */
		if (preg_match('/\s/', $_POST['charset']))
			$input_errors[] = "Spaces, tabs and line breaks aren't allowed in the " .
				"character set: the configuration file format ends the field at the " .
				"first whitespace, so everything after it would be silently dropped.";

		/* A REPEATED character breaks the encoding both ways.
		
		   Rendering maps digit d to charset[d]; parsing maps a character back
		   with strchr(), which finds the FIRST occurrence. With any duplicate,
		   every digit that renders to a later copy parses back as the earlier
		   one, so the voucher decodes to a different number than it encoded.
		   It is completely silent -- the roll prints without complaint, the
		   tickets are handed out, and the majority of guests are told their
		   voucher is invalid with nothing anywhere pointing at the alphabet. */
		$dupes = array();
		foreach (count_chars($_POST['charset'], 1) as $byte => $count)
			if ($count > 1)
				$dupes[] = chr($byte);
		if ($dupes)
			$input_errors[] = "The character set must not repeat a character. " .
				"Repeated: " . htmlspecialchars(implode(' ', $dupes)) . ". A voucher is " .
				"a number written in this alphabet, so a repeated character makes it " .
				"impossible to read back and most vouchers would be rejected.";

		if (strlen($_POST['charset']) > 255)
			$input_errors[] = "The character set must be 255 characters or fewer.";
	}
	if (!empty($_POST['rollbits']) && (!is_numeric($_POST['rollbits']) || ($_POST['rollbits'] < 1) || ($_POST['rollbits'] > 31))) {
		$input_errors[] = "# of Bits to store Roll Id needs to be between 1..31.";
	}
	if (!empty($_POST['ticketbits']) && (!is_numeric($_POST['ticketbits']) || ($_POST['ticketbits'] < 1) || ($_POST['ticketbits'] > 16))) {
		$input_errors[] = "# of Bits to store Ticket Id needs to be between 1..16.";
	}
	/* is_numeric(), not !empty(): the help text and the tool both allow 0, but
	   !empty("0") is false so 0 skipped validation entirely. */
	if (isset($_POST['checksumbits']) && $_POST['checksumbits'] !== "" &&
	    (!is_numeric($_POST['checksumbits']) || ($_POST['checksumbits'] < 0) || ($_POST['checksumbits'] > 31))) {
		$input_errors[] = "# of Bits to store checksum needs to be between 0..31.";
	}
	/* The anti-forgery floor. Whatever Roll, Ticket and Checksum bits leave of
	   the 64 holds the magic number, and magic + checksum together are the only
	   thing that makes a made-up code fail -- so the redundancy is exactly
	   64 - Roll - Ticket, however the remainder is split. Capping Roll + Ticket
	   at 32 therefore keeps at least 32 bits of it at every legal setting.
	   The old page permitted 31 + 16 + 16, which leaves 1 magic bit and 17 bits
	   of redundancy in total: about 131000 guesses, a weekend at 10 tries a
	   second. The voucher binary refuses the same combination, because
	   voucher.cfg is hand-editable and is also rewritten from a restored
	   config.xml that never passed through this page. */
	if (is_numeric($_POST['rollbits'] ?? null) && is_numeric($_POST['ticketbits'] ?? null) &&
	    (($_POST['rollbits'] + $_POST['ticketbits']) > 32)) {
		$input_errors[] = "# of Roll Bits plus # of Ticket Bits must not exceed 32, so that " .
			"at least 32 of each voucher's 64 bits are left as verifiable magic number and " .
			"checksum. The defaults are 16 and 10.";
	}
	/* 'magic' is free text and is interpolated straight into voucher.cfg. If it
	   is blanked or non-numeric the %llu in the tool's five-field fscanf eats
	   the charset instead and the config line silently mis-parses. */
	if (isset($_POST['magic']) && ($_POST['magic'] !== "") &&
	    !preg_match('/^\d+$/', (string) $_POST['magic'])) {
		/* Digits only, not is_numeric(). is_numeric() is true for "1.5", "1e5"
		   and "5 " -- all of which pass a "> 0" test and are then written
		   verbatim into voucher.cfg, where the tool's %llu stops at the '.',
		   'e' or space and the rest of the line mis-parses. The result is a
		   total, silent outage of the feature reached from a validated form
		   field: every print fails and every guest login fails. */
		$input_errors[] = "The magic number must be a whole number, digits only.";
	}
	if (!empty($_POST['saveinterval']) && (!is_numeric($_POST['saveinterval']) || ($_POST['saveinterval'] < 1))) {
		$input_errors[] = "Save interval in minutes cant be negative.";
	}

	if (empty($input_errors)) {
        $config['voucher']['enable'] = !empty($_POST['enable']) ? true : false;
        $config['voucher']['charset'] = $_POST['charset'] ?? null;
        $config['voucher']['rollbits'] = $_POST['rollbits'] ?? null;
        $config['voucher']['ticketbits'] = $_POST['ticketbits'] ?? null;
        $config['voucher']['checksumbits'] = $_POST['checksumbits'] ?? null;
        $config['voucher']['magic'] = $_POST['magic'] ?? null;
        $config['voucher']['saveinterval'] = $_POST['saveinterval'] ?? null;
        $config['voucher']['msgnoaccess'] = $_POST['msgnoaccess'] ?? null;
        $config['voucher']['msgexpired'] = $_POST['msgexpired'] ?? null;
        /* A config restored from an older image still carries these. They are
           dead weight -- nothing reads them any more -- and leaving them would
           suggest the RSA scheme is still in play. */
        unset($config['voucher']['publickey']);
        unset($config['voucher']['privatekey']);

        if (!empty($_POST['regenkey'])) {
            /* Count what is about to be orphaned before replacing the secret:
               the confirm() dialog on the checkbox is the only other guard and
               it never fires with JavaScript off. */
            $orphaned = 0;
            voucher_lock();
            foreach ($config['voucher']['roll'] as $rollent)
                $orphaned += count(voucher_read_active_db($rollent['number'] ?? 0));
            voucher_unlock();
            if (voucher_new_key()) {
                $savemsg = "A new voucher secret was generated. Every voucher " .
                    "printed before now is now invalid";
                $savemsg .= $orphaned
                    ? ", including $orphaned currently active voucher(s)." : ".";
                voucher_log(LOG_NOTICE, "voucher secret regenerated by an " .
                    "administrator; $orphaned active voucher(s) orphaned");
            } else {
                $input_errors[] = "Could not generate a new voucher secret. " .
                    "The existing one is unchanged.";
            }
        }

        if (empty($input_errors)) {
            voucher_lock();
            write_config();
            voucher_configure();
            voucher_unlock();
            /* After write_config() above, so $config has been re-read from disk
               and a cleared checkbox is absent rather than false -- but tested
               the same way as voucher_configure() so the two cannot disagree. */
            if (isset($config['voucher']['enable']) && $config['voucher']['enable'] !== false
                && !isset($config['captiveportal']['enable'])) {
                $savemsg = trim(($savemsg ?? '') . " Don't forget to configure and enable Captive Portal.");
            }
        }
	}
}

/* Reported here, after the POST handler's unset($input_errors), so a failed
   secret bootstrap is shown on both a GET and a POST. */
if ($keygen_error !== "")
	$input_errors[] = $keygen_error;
?>
<?php include("fbegin.inc"); ?>
<script type="text/javascript">
<!--
function enable_change(enable_change) {
	var endis;
	endis = !(document.iform.enable.checked || enable_change);
	
	document.iform.charset.disabled = endis;
	document.iform.rollbits.disabled = endis;
	document.iform.ticketbits.disabled = endis;
	document.iform.saveinterval.disabled = endis;
	document.iform.checksumbits.disabled = endis;
	document.iform.magic.disabled = endis;
	/* The publickey/privatekey textareas are gone. Leaving their names here
	   would throw a TypeError on the undefined element and every statement
	   BELOW it -- msgnoaccess, msgexpired -- would stop running, so those
	   fields would stay disabled and Save would post nothing. */
	document.iform.regenkey.disabled = endis;
	document.iform.msgnoaccess.disabled = endis;
	document.iform.msgexpired.disabled = endis;
}
//-->
</script>
<?php if (!empty($input_errors)) print_input_errors($input_errors); ?>
<?php if (!empty($savemsg)) print_info_box($savemsg); ?>
<form action="services_captiveportal_vouchers.php" method="post" enctype="multipart/form-data" name="iform" id="iform">
<table width="100%" border="0" cellpadding="0" cellspacing="0" summary="tab pane">
  <tr><td class="tabnavtbl">
  <ul id="tabnav">
<?php 
   	$tabs = array('Captive Portal' => 'services_captiveportal.php',
           		  'Pass-through MAC' => 'services_captiveportal_mac.php',
           		  'Allowed IP addresses' => 'services_captiveportal_ip.php',
           		  'Users' => 'services_captiveportal_users.php',
           		  'Vouchers' => 'services_captiveportal_vouchers.php',
           		  'File Manager' => 'services_captiveportal_filemanager.php');
	dynamic_tab_menu($tabs);
?> 
  </ul>
  </td></tr>
  <tr>
  <td class="tabcont">
  <table width="100%" border="0" cellpadding="6" cellspacing="0" summary="checkbox pane">
	<tr> 
	  <td width="22%" valign="top" class="vtable">&nbsp;</td>
	  <td width="78%" class="vtable">
		<input name="enable" type="checkbox" value="yes" <?php if (!empty($pconfig['enable'])) echo "checked"; ?> onClick="enable_change(false)">
		<strong>Enable Vouchers</strong></td>
	</tr>
	<tr>
	  <td valign="top" class="vncell">Voucher Rolls</td>
	  <td class="vtable">

              <table width="100%" border="0" cellpadding="0" cellspacing="0" summary="content pane">
                <tr>
                  <td width="10%" class="listhdrr">Roll#</td>
                  <td width="20%" class="listhdrr">Minutes/Ticket</td>
                  <td width="20%" class="listhdrr"># of Tickets</td>
                  <td width="35%" class="listhdr">Comment</td>
                  <td width="15%" class="list"></td>
		</tr>
	<?php $i = 0; foreach($a_roll as $rollent): ?>
		<tr>
                  <td class="listlr">
                    <?=htmlspecialchars($rollent['number'] ?? ''); ?>&nbsp;
                  </td>
                  <td class="listr">
                    <?=htmlspecialchars($rollent['minutes'] ?? '');?>&nbsp;
                  </td>
                  <td class="listr">
                    <?=htmlspecialchars($rollent['count'] ?? '');?>&nbsp;
                  </td>
                  <td class="listr">
                    <?=htmlspecialchars($rollent['comment'] ?? ''); ?>&nbsp;
                  </td>
                  <td valign="middle" nowrap class="list"> 
                  <?php if (!empty($pconfig['enable'])): ?> 
                    <a href="services_captiveportal_vouchers_edit.php?id=<?=$i; ?>"><img src="e.gif" title="edit voucher" width="17" height="17" border="0" alt="edit voucher"></a>
					<input name="del_<?=$i;?>" type="image" src="x.gif" width="17" height="17" title="delete voucher roll" alt="delete voucher roll" onclick="return confirm('Do you really want to delete this voucher roll and render all vouchers from this roll invalid?')">
                    <a href="services_captiveportal_vouchers.php?act=csv&amp;id=<?=$i; ?>"><img src="log_s.gif" title="generate vouchers for this roll to CSV file" width="11" height="15" border="0" alt="generate vouchers for this roll to CSV file"></a>
                    <?php endif;?>
                  </td>
		</tr>
	<?php $i++; endforeach; ?>
		<tr> 
			  <td class="list" colspan="4"></td>
              <?php if (!empty($pconfig['enable'])): ?> 
			  <td class="list"> <a href="services_captiveportal_vouchers_edit.php"><img src="plus.gif" title="add voucher" width="17" height="17" border="0" alt="add voucher"></a></td>
              <?php endif;?>
		      </tr>
        </table>     
<?php if (!empty($pconfig['enable'])): ?> 
Create, generate and activate Rolls with Vouchers that allow access through the 
captive portal for the configured time. Once a voucher is activated, 
its clock is started and runs uninterrupted until it expires. During that
time, the voucher can be re-used from the same or a different computer. If the voucher 
is used again from another computer, the previous session is stopped.
<?php else: ?>
Enable Voucher support first using the checkbox above and hit Save at the bottom.</td>
<?php endif;?>
	</tr>
	<tr>
      <td valign="top" class="vncell">Voucher key</td>
      <td class="vtable">
        <?php if ($pconfig['keyfp'] === false): ?>
          <span class="red"><strong>present but unusable</strong></span> &ndash; the stored
          secret is not 32 bytes of base64. Tick the box below and save to replace it.
          Vouchers already printed will stop working.
        <?php elseif ($pconfig['keyfp'] === ''): ?>
          not yet generated
        <?php else: ?>
          fingerprint <?=htmlspecialchars($pconfig['keyfp']);?>
        <?php endif; ?>
        <br>
        <input name="regenkey" type="checkbox" value="yes" id="regenkey"
               onclick="return !this.checked || confirm('Generating a new voucher key makes every already-printed voucher invalid. Continue?')">
        Generate a new voucher key
        <br>
        A single 256-bit secret, generated on this firewall, used both to print and to
        validate vouchers. There is no key to paste in and none to copy out; only its
        fingerprint is shown, so you can see at a glance whether it changed. It is stored
        in the configuration file, so anyone holding a configuration backup can print
        valid vouchers.</td>
	</tr>
	<tr> 
       <td width="22%" valign="top" class="vncellreq">Character set</td>
       <td width="78%" class="vtable">
         <input name="charset" type="text" class="formfld" id="charset" size="80" value="<?=htmlspecialchars($pconfig['charset'] ?? '');?>">
         <br>
         Tickets are generated with the specified character set. It should contain printable characters (numbers, lower case and upper case letters) that are hard to confuse with others. Avoid e.g. 0/O and l/1.</td>
    </tr>
	<tr> 
       <td width="22%" valign="top" class="vncellreq"># of Roll Bits</td>
       <td width="78%" class="vtable">
         <input name="rollbits" type="text" class="formfld" id="rollbits" size="2" value="<?=htmlspecialchars($pconfig['rollbits'] ?? '');?>">
         <br>
         Reserves a range in each voucher to store the Roll# it belongs to. Allowed range: 1..31. Roll Bits plus Ticket Bits must not exceed 32: whatever those two and the Checksum leave of each voucher's 64 bits holds the magic number, and that is what lets the firewall reject a made-up code.</td>
    </tr>
	<tr> 
       <td width="22%" valign="top" class="vncellreq"># of Ticket Bits</td>
       <td width="78%" class="vtable">
         <input name="ticketbits" type="text" class="formfld" id="ticketbits" size="2" value="<?=htmlspecialchars($pconfig['ticketbits'] ?? '');?>">
         <br>
         Reserves a range in each voucher to store the Ticket# it belongs to. Allowed range: 1..16. Using 16 bits allows a roll to have up to 65535 vouchers. A bit array, stored in RAM and in the config, is used to mark if a voucher has been used. A bit array for 65535 vouchers requires 8 KB of storage.</td>
    </tr>
	<tr> 
       <td width="22%" valign="top" class="vncellreq"># of Checksum Bits</td>
       <td width="78%" class="vtable">
         <input name="checksumbits" type="text" class="formfld" id="checksumbits" size="2" value="<?=htmlspecialchars($pconfig['checksumbits'] ?? '');?>">
         <br>
         Reserves a range in each voucher to store a simple checksum over Roll# and Ticket#. Allowed range is 0..31. It does not change how hard a voucher is to forge -- the magic number grows by whatever the checksum gives up -- it just makes a mistyped code report a checksum error rather than a wrong Roll#.</td>
    </tr>
	<tr> 
       <td width="22%" valign="top" class="vncellreq">Magic Number</td>
       <td width="78%" class="vtable">
         <input name="magic" type="text" class="formfld" id="magic" size="20" value="<?=htmlspecialchars($pconfig['magic'] ?? '');?>">
         <br>
         Magic number stored in and verified in every voucher. It is 64 minus Roll minus Ticket minus Checksum bits wide -- 33 bits with the defaults. Its WIDTH is what makes a made-up code fail (width plus Checksum Bits is the number of bits a forger would have to guess); its value does not need to be secret and does not make this firewall's vouchers unique -- the voucher key does that. Must be a positive integer.</td>
    </tr>
	<tr> 
       <td width="22%" valign="top" class="vncellreq">Save Interval</td>
       <td width="78%" class="vtable">
         <input name="saveinterval" type="text" class="formfld" id="saveinterval" size="4" value="<?=htmlspecialchars($pconfig['saveinterval'] ?? '');?>">
         Minutes<br>
         The list of active and used vouchers can be stored in the system's configuration file once every x minutes to survive power outages. No save is done if no new vouchers have been activated.  Enter 0 to never write runtime state to XML config.</td>
    </tr>
	<tr> 
       <td width="22%" valign="top" class="vncellreq">Invalid Voucher Message</td>
       <td width="78%" class="vtable">
         <input name="msgnoaccess" type="text" class="formfld" id="msgnoaccess" size="80" value="<?=htmlspecialchars($pconfig['msgnoaccess'] ?? '');?>">
         Error message displayed for invalid vouchers on captive portal error page ($PORTAL_MESSAGE$).</td>
    </tr>
	<tr> 
       <td width="22%" valign="top" class="vncellreq">Expired Voucher Message</td>
       <td width="78%" class="vtable">
         <input name="msgexpired" type="text" class="formfld" id="msgexpired" size="80" value="<?=htmlspecialchars($pconfig['msgexpired'] ?? '');?>">
         Error message displayed for expired vouchers on captive portal error page ($PORTAL_MESSAGE$).</td>
    </tr>
    <tr>
       <td width="22%" valign="top">&nbsp;</td>
       <td width="78%">
        <input name="Submit" type="submit" class="formbtn" value="Save" onClick="enable_change(true)">
       </td>
    </tr>
    <tr>
     <td colspan="2" class="list"><p class="vexpl">
     <span class="red"><strong> Note:<br>   </strong></span>
      Changing any Voucher parameter (apart from managing the list of Rolls) on this page will render existing vouchers useless if they were generated with different settings. That includes generating a new voucher key.
      </p>
     </td>
    </tr>
  </table>
  </td>
  </tr>
  </table>
</form>
<script type="text/javascript">
<!--
enable_change(false);
//-->
</script>
<?php include("fend.inc"); ?>
