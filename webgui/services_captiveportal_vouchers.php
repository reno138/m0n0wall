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
            system("/usr/local/bin/voucher -c {$g['varetc_path']}/voucher.cfg -K {$g['varetc_path']}/voucher.key -p $number $count");
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
$pconfig['keyfp'] = !empty($config['voucher']['fpekey'])
    ? substr(hash('sha256', base64_decode($config['voucher']['fpekey'], true) ?: ''), 0, 16)
    : '';
$pconfig['msgnoaccess'] = $config['voucher']['msgnoaccess'] ?? null;
$pconfig['msgexpired'] = $config['voucher']['msgexpired'] ?? null;

if ($_POST) {

	unset($input_errors);
	$pconfig = $_POST;

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
	$badchars = array('"' => "Double quotes", ',' => "Commas", ' ' => "Spaces");
	foreach ($badchars as $bc => $bcname) {
		if (!empty($_POST['charset']) && (strpos($_POST['charset'], $bc) !== false)) {
			$input_errors[] = "$bcname aren't allowed in the character set.";
		}
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
	if (!is_numeric($_POST['magic'] ?? null) || ($_POST['magic'] < 0)) {
		$input_errors[] = "The magic number must be a positive integer.";
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
        $config['voucher']['publickey'] = base64_encode($_POST['publickey'] ?? '');
        $config['voucher']['privatekey'] = base64_encode($_POST['privatekey'] ?? '');
        $config['voucher']['msgnoaccess'] = $_POST['msgnoaccess'] ?? null;
        $config['voucher']['msgexpired'] = $_POST['msgexpired'] ?? null;
        voucher_lock();
		write_config();
        voucher_configure();
        voucher_unlock();
        if (isset($config['voucher']['enable']) && !isset($config['captiveportal']['enable'])) {
            $savemsg = "Don't forget to configure and enable Captive Portal.";
        }
	}
}
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
	document.iform.publickey.disabled = endis;
	document.iform.privatekey.disabled = endis;
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
      <td valign="top" class="vncellreq">Voucher public key</td>
      <td class="vtable">
        <textarea name="publickey" cols="65" rows="4" id="publickey" class="formpre"><?=htmlspecialchars($pconfig['publickey'] ?? '');?></textarea>
        <br>
    Paste an RSA public key (64 Bit or smaller) in PEM format here. This key is used to decrypt vouchers.</td>
	</tr>
	<tr>
      <td valign="top" class="vncell">Voucher private key</td>
      <td class="vtable">
        <textarea name="privatekey" cols="65" rows="5" id="privatekey" class="formpre"><?=htmlspecialchars($pconfig['privatekey'] ?? '');?></textarea>
        <br>
    Paste an RSA private key (64 Bit or smaller) in PEM format here. This key is only used to generate encrypted vouchers and doesn't need to be available if the vouchers have been generated offline.</td>
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
         Reserves a range in each voucher to store the Roll# it belongs to. Allowed range: 1..31. Sum of Roll+Ticket+Checksum bits must be one Bit less than the RSA key size.</td>
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
         Reserves a range in each voucher to store a simple checksum over Roll# and Ticket#. Allowed range is 0..31.</td>
    </tr>
	<tr> 
       <td width="22%" valign="top" class="vncellreq">Magic Number</td>
       <td width="78%" class="vtable">
         <input name="magic" type="text" class="formfld" id="magic" size="20" value="<?=htmlspecialchars($pconfig['magic'] ?? '');?>">
         <br>
         Magic number stored in every voucher. Verified during voucher check. Size depends on how many bits are left by Roll+Ticket+Checksum bits. If all bits are used, no magic number will be used and checked.</td>
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
      Changing any Voucher parameter (apart from managing the list of Rolls) on this page will render existing vouchers useless if they were generated with different settings.
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
