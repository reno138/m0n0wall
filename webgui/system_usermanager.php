#!/usr/local/bin/php
<?php 
/*
	$Id: system_usermanager.php
	part of m0n0wall (http://m0n0.ch/wall)

	Copyright (C) 2005 Paul Taylor <paultaylor@winn-dixie.com>.
	All rights reserved. 

	Copyright (C) 2003-2005 Manuel Kasper <mk@neon1.net>.
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

require("guiconfig.inc");

// The page title for non-admins
$pgtitle = array("System", "User password");

if (($_SERVER['REMOTE_USER'] ?? null) === ($config['system']['username'] ?? null)) { 
    
    // Page title for main admin
    $pgtitle = array("System", "User manager");

    $id = $_GET['id'] ?? null;
    if (isset($_POST['id']))
	   $id = $_POST['id'];
       
    if (!is_array($config['system']['user'] ?? null)) {
    	$config['system']['user'] = array();
    }
    admin_users_sort();
    $a_user = &$config['system']['user'];
  	
    if ($_POST) {

		$deldone = false;
		foreach ($_POST as $pn => $pv) {
			if (preg_match("/^del_(\d+)_x$/", $pn, $matches)) {
				$id = $matches[1];
				if (!empty($a_user[$id])) {
		    	    $userdeleted = $a_user[$id]['name'] ?? null;
		    		unset($a_user[$id]);
		    		write_config();
					$retval = system_password_configure();
					$savemsg = get_std_save_message($retval);
					$savemsg = "User ".$userdeleted." successfully deleted<br>";
		    	}	
				$deldone = true;
				break;
			}
		}

		if (!$deldone) {
	    	unset($input_errors);
	    	$pconfig = $_POST;
    
	    	/* input validation */
	    	if (isset($id) && (!empty($a_user[$id]))) {
	    		$reqdfields = explode(" ", "username");
	    		$reqdfieldsn = explode(",", "Username");
	    	} else {
	    		$reqdfields = explode(" ", "username password");
	    		$reqdfieldsn = explode(",", "Username,Password");
	    	}
    	
	    	do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
    	
	    	if (preg_match("/[^a-zA-Z0-9\.\-_]/", $_POST['username'] ?? ''))
	    		$input_errors[] = "The username contains invalid characters.";

			if(($_POST['username'] ?? null)==($config['system']['username'] ?? null)) {
				$input_errors[] = "Username can not match the administrator username!";
			}   		
    		
	    	if ((!empty($_POST['password'])) && ($_POST['password'] != ($_POST['password2'] ?? null)))
	    		$input_errors[] = "The passwords do not match.";
			if (!empty($_POST['password']) && strpos($_POST['password'], ":") !== false)
				$input_errors[] = "The password may not contain colons (:).";

	       	if (empty($input_errors) && !(isset($id) && !empty($a_user[$id]))) {
	    		/* make sure there are no dupes */
	    		foreach ($a_user as $userent) {
	    			if (($userent['name'] ?? null) == ($_POST['username'] ?? null)) {
	    				$input_errors[] = "Another entry with the same username already exists.";
	    				break;
	    			}
	    		}
	    	}

			if(!isset($groupindex[$_POST['groupname'] ?? ''])) {
				$input_errors[] = "Group does not exist, please define the group before assigning users.";
			}
    	
	    	if (empty($input_errors)) {
    	
	    		if (isset($id) && !empty($a_user[$id]))
	    			$userent = $a_user[$id];
    		
	    		$userent['name'] = $_POST['username'] ?? null;
	    		$userent['fullname'] = $_POST['fullname'] ?? null;
	    		$userent['groupname'] = $_POST['groupname'] ?? null;
    		
	    		if (!empty($_POST['password']))
	    			$userent['password'] = system_password_hash($_POST['password']);
    		
	    		if (isset($id) && !empty($a_user[$id]))
	    			$a_user[$id] = $userent;
	    		else
	    			$a_user[] = $userent;
    		
	    		write_config();
				$retval = system_password_configure();
				$savemsg = get_std_save_message($retval);
			
				header("Location: system_usermanager.php");
	    	}
		}
    }

?>
<?php include("fbegin.inc"); ?>
<?php if (!empty($input_errors)) print_input_errors($input_errors); ?>
<?php if (!empty($savemsg)) print_info_box($savemsg); ?>
<form action="system_usermanager.php" method="post" name="iform" id="iform">
<table width="100%" border="0" cellpadding="0" cellspacing="0" summary="tab pane">
  <tr><td class="tabnavtbl">
  <ul id="tabnav">
	<?php 
    	$tabs = array('Users' => 'system_usermanager.php',
            		  'Groups' => 'system_groupmanager.php');
		dynamic_tab_menu($tabs);
    ?>     
  </ul>
  </td></tr>    
<tr>
  <td class="tabcont">
<?php
if(($_GET['act'] ?? null)=="new" || ($_GET['act'] ?? null)=="edit" || !empty($input_errors)){
	if(($_GET['act'] ?? null)=="edit"){
		if (isset($id) && !empty($a_user[$id])) {
	       $pconfig['username'] = $a_user[$id]['name'] ?? null;
	       $pconfig['fullname'] = $a_user[$id]['fullname'] ?? null;
	       /* $a_group does not exist in this file; the user entry carries it */
	       $pconfig['groupname'] = $a_user[$id]['groupname'] ?? null;
        }
	}	
?>
              <table width="100%" border="0" cellpadding="6" cellspacing="0" summary="content pane">
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Username</td>
                  <td width="78%" class="vtable"> 
                    <input name="username" type="text" class="formfld" id="username" size="20" value="<?=htmlspecialchars($pconfig['username'] ?? '');?>"> 
                    </td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncellreq">Password</td>
                  <td width="78%" class="vtable"> 
                    <input name="password" type="password" class="formfld" id="password" size="20" value=""> <br>
					<input name="password2" type="password" class="formfld" id="password2" size="20" value="">
&nbsp;(confirmation)					</td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncell">Full name</td>
                  <td width="78%" class="vtable"> 
                    <input name="fullname" type="text" class="formfld" id="fullname" size="20" value="<?=htmlspecialchars($pconfig['fullname'] ?? '');?>">
                    <br>
                    User's full name, for your own information only</td>
                </tr>
                <tr> 
                  <td width="22%" valign="top" class="vncell">Group Name</td>
                  <td width="78%" class="vtable">
				  <select name="groupname" class="formfld" id="groupname">
                      <?php if (is_array($config['system']['group'] ?? null) && count($config['system']['group']) > 0): ?>
                      <?php foreach ($config['system']['group'] as $group): ?>
                      <option value="<?=$group['name'] ?? '';?>" <?php if (($group['name'] ?? null) == ($pconfig['groupname'] ?? null)) echo "selected"; ?>>
                      <?=htmlspecialchars($group['name'] ?? '');?>
                      </option>
                      <?php endforeach; ?>
                      <?php endif; ?>
                    </select>                   
                    <br>
                    The admin group to which this user is assigned.</td>
                </tr>                
                <tr> 
                  <td width="22%" valign="top">&nbsp;</td>
                  <td width="78%"> 
                    <input name="save" type="submit" class="formbtn" value="Save"> 
            		<?php if (isset($id) && !empty($a_user[$id])): ?>
                    <input name="id" type="hidden" value="<?=htmlspecialchars($id);?>">
		            <?php endif; ?>
                  </td>
                </tr>
              </table>
<?php
} else {
?>
     <table width="100%" border="0" cellpadding="0" cellspacing="0" summary="user list pane">
        <tr>
           <td width="35%" class="listhdrr">Username</td>
           <td width="20%" class="listhdrr">Full name</td>
           <td width="20%" class="listhdrr">Group</td>                  
           <td width="10%" class="list"></td>
		</tr>
	<?php $i = 0; foreach($a_user as $userent): ?>
		<tr>
                  <td class="listlr">
                    <?=htmlspecialchars($userent['name'] ?? ''); ?>&nbsp;
                  </td>
                  <td class="listr">
                    <?=htmlspecialchars($userent['fullname'] ?? '');?>&nbsp;
                  </td>
                  <td class="listbg">
                    <?=htmlspecialchars($userent['groupname'] ?? ''); ?>&nbsp;
                  </td>
                  <td valign="middle" nowrap class="list"> <a href="system_usermanager.php?act=edit&amp;id=<?=$i; ?>"><img src="e.gif" title="edit user" width="17" height="17" border="0" alt="edit user"></a>
                     &nbsp;<input name="del_<?=$i;?>" type="image" src="x.gif" width="17" height="17" title="delete user" alt="delete user" onclick="return confirm('Do you really want to delete this user?')"></td>
		</tr>
	<?php $i++; endforeach; ?>
	    <tr> 
			<td class="list" colspan="3"></td>
			<td class="list"> <a href="system_usermanager.php?act=new"><img src="plus.gif" title="add user" width="17" height="17" border="0" alt="add user"></a></td>
		</tr>
		<tr>
			<td colspan="3">
		      Additional webGUI users can be added here.  User permissions are determined by the admin group they are a member of.
			</td>
		</tr>
 </table>
<?php } ?>
     
  </td>
  </tr>
  </table>
</form>
<?php 
} else { // end of admin user code, start of normal user code
	if (isset($_POST['save'])) {

	    unset($input_errors);
    
    	/* input validation */
   		$reqdfields = explode(" ", "password");
   		$reqdfieldsn = explode(",", "Password");
    	
    	do_input_validation($_POST, $reqdfields, $reqdfieldsn, $input_errors);
    	
    	if (($_POST['password'] ?? null) != ($_POST['password2'] ?? null))
      		$input_errors[] = "The passwords do not match.";
    	
		if (empty($input_errors)) {
			//all values are okay --> saving changes
			$config['system']['user'][$userindex[$_SERVER['REMOTE_USER'] ?? ''] ?? '']['password']=system_password_hash(trim($_POST['password'] ?? ''));

			write_config();
			$retval = system_password_configure();
			$savemsg = get_std_save_message($retval);
			$savemsg = "Password successfully changed<br>";
		}		
	}

	
?>
<?php include("fbegin.inc"); ?>
<?php if (!empty($input_errors)) print_input_errors($input_errors); ?>
<?php if (!empty($savemsg)) print_info_box($savemsg); ?>
      <form action="system_usermanager.php" method="post" name="iform" id="iform">
         <table width="100%" border="0" cellpadding="6" cellspacing="0" summary="password change pane">
            <tr> 
              <td colspan="2" valign="top" class="listtopic"><?=htmlspecialchars($_SERVER['REMOTE_USER'] ?? '')?>'s Password</td>
            </tr>
		    <tr> 
		      <td width="22%" valign="top" class="vncell">Password</td>
		      <td width="78%" class="vtable"> <input name="password" type="password" class="formfld" id="password" size="20"> 
		        <br> <input name="password2" type="password" class="formfld" id="password2" size="20"> 
		        &nbsp;(confirmation) <br> <span class="vexpl">Select a new password</span></td>
		    </tr>
            <tr> 
              <td width="22%" valign="top">&nbsp;</td>
              <td width="78%"> 
                <input name="save" type="submit" class="formbtn" value="Save"> 
              </td>
            </tr>		    
         </table>
      </form>		    

<?php 
} // end of normal user code ?>
<?php include("fend.inc"); ?>
