<?php
/**
 * Passwd ExpressionEngine Plugin
 *
 * Allows users to change their password or force them
 * to change their password with a simple template tag.
 *
 * Expression Engine 1.x (tested 1.6.7 - 1.7.1)
 *
 * @package   Passwd
 * @version   1.0
 * @author    Jeremy Messenger <jlmessengertech+githib@gmail.com>
 * @copyright 2011 Jeremy Messenger
 * @license   LGPL <http://www.gnu.org/licenses/lgpl.html>
 * @link      http://jlmessenger.com
 */

/**
 * Required Plugin Array for CP
 */
$plugin_info = array(
	'pi_name' => 'Passwd',
	'pi_version' => '1.0',
	'pi_author' => 'Jeremy Messenger',
	'pi_author_url' => 'http://jlmessenger.com',
	'pi_description' => 'Simple user password changer',
	'pi_usage' => Passwd::usage()
);

/**
 * Passwd Plugin class
 * @package   Passwd
 * @version   1.0
 */
class Passwd
{
	/**
	 * Final tag content
	 * @var string
	 */
	var $return_data = '';
	
	/**
	 * Provides tag {exp:passwd}
	 * Class is initialized by EE template parser
	 */
	function Passwd()
	{
		global $TMPL, $IN, $FNS, $SESS, $DB, $LOC, $PREFS;
		
		$conditionals = array(
				'error' => FALSE,
				'changed' => FALSE,
				'password_expired' => FALSE
			);
		
		// is user a member, and logged in?
		$member_id = $SESS->userdata['member_id'];
		if ($member_id <= 0 || !is_numeric($member_id))
		{
			// user does not have permission
			$this->$return_data = $TMPL->no_results();
			return;
		}
		
		$old_field = $TMPL->fetch_param('old_password');
		$new_field = $TMPL->fetch_param('new_password');
		$expired_passwds = $TMPL->fetch_param('expired_passwords');
		$secure = $TMPL->fetch_param('secure') == 'y';
		
		if ($new_field === FALSE)
		{
			// required parameter is missing
			$this->$return_data = $TMPL->no_results();
			return;
		}
		
		$new_pass = $IN->GBL($new_field);
		if ($old_field !== FALSE)
			$old_pass = $IN->GBL($old_field);
		else
			$old_pass = FALSE;
		
		$sql = "SELECT username, password FROM exp_members WHERE member_id = '$member_id'";
		$query = $DB->query($sql);
		if ($query->num_rows == 0)
			return; // user not in db?
		else
			$user_data = $query->row;
		
		// check if password is expired (in expired passwords list)
		$bad_pass = array();
		if ($expired_passwds !== FALSE && $expired_passwds != '')
		{
			$bad_pass = explode('|', $expired_passwds);
			foreach ($bad_pass as $pass)
			{
				$bhash = $FNS->hash($pass);
				if ($user_data['password'] == $bhash)
					$conditionals['password_expired'] = TRUE;
			}
		}
		
		if ($new_pass !== FALSE && !is_null($new_pass))
		{
			if (is_array($new_pass))
			{
				// ensure all version match (and are not blank)
				if (count($new_pass) == 0)
					$new_pass = '';
				else if (count($new_pass) >= 1)
				{
					$p1 = array_pop($new_pass);
					while (($p2 = array_pop($new_pass)) != NULL)
					{
						if ($p2 == '' && $p1 != $p2)
						{
							$conditionals['error'] == TRUE;
							break;
						}
					}
					$new_pass = $p1;
				}
			}
			
			if (!$conditionals['error'] && $old_field !== FALSE && !$conditionals['password_expired'])
			{
				// not first login, and tag is configured to check old field
				if ($old_pass === FALSE)
					$conditionals['error'] == TRUE;
				else
				{
					$old_hash = $FNS->hash($old_pass);
					if ($user_data['password'] != $old_hash)
						$conditionals['error'] = TRUE;
				}
			}
			
			if ($new_pass == '') // check for blank password
				$conditionals['error'] = TRUE;
			if (in_array($new_pass, $bad_pass)) // ensure new passwod is not in expired list
				$conditionals['error'] = TRUE;
			elseif (!$conditionals['error'])
			{
				// validate password with EE rules
				if ( ! class_exists('Validate'))
				{
					require PATH_CORE.'core.validate'.EXT;
				}
				
				$VAL = new Validate(array(
						'fetch_lang'		=> TRUE,
						'username'			=> $user_data['username'],
						'password'			=> $new_pass,
						'password_confirm'	=> $new_pass
		 			));

				$VAL->validate_password();
				$conditionals['error'] = count($VAL->errors) > 0;
			}
			
			if (!$conditionals['error'])
			{
				// still a green light, time to go!
				$new_hash = $FNS->hash($new_pass);
				
				$sql = "UPDATE exp_members SET password = '$new_hash' WHERE member_id = '$member_id'";
				$DB->query($sql);
				
				// update login cookie with new password hash
				$FNS->set_cookie($SESS->c_password, $new_hash, 0);
				
				$conditionals['changed'] = TRUE;
				$conditionals['password_expired'] = FALSE;
			}
		}
		
		// write out tags
		$tagdata = $FNS->prep_conditionals($TMPL->tagdata, $conditionals);
		
		if (array_key_exists('passwd_form', $TMPL->var_pair))
		{
			$this_page = $FNS->fetch_current_uri();
			if ($secure)
			{
				$colon = strpos($this_page, ':');
				if ($colon !== FALSE)
				{
					$prefix = strtolower(substr($this_page, 0, $colon));
					if ($prefix == 'http')
						$this_page = 'https'.substr($this_page, $colon);
				}
			}
			
			$tagdata = str_replace(
				array(LD.'passwd_form'.RD, LD.SLASH.'passwd_form'.RD),
				array("<form method=\"post\" action=\"$this_page\">", '</form>'),
				$tagdata);
		}
		$this->return_data = $tagdata;
	}
	
	/**
	 * Usage examples for the Passwd plugin
	 * @return string Passwd Usage Data
	 */
	function usage()
	{
		return <<<EOL
PARAMETERS:
* new_password = The name of the form field or field array which supply the new user password
* expired_passwords = (optional) A pipe '|' separated list of disallowed/expired passwords
* old_password = (optional) The form field with the current password, only checked if not expired
* secure = (optional) Set to "y" to post the new password using https

VARIABLES:
* {passwd_form} {/passwd_form} = Wrap your change password form and writes HTML <form> elements

CONDITIONALS:
* if no_results = If a required parameter is missing, or the user is not a logged in user
* if error = The submitted password was blank, did not match, or was not secure per EE settings
* if changed = The user's password has been changed
* if password_expired = The user's current password is in the expired_passwords list

EXAMPLE:
{exp:passwd
 expired_passwords="changeme|firstlogin"
 old_password="oldpass"
 new_password="newpass"
 secure="y"
}
{if changed}
  <p>Password Changed!</p>
{if:elseif error}
  <p>Passwords did not match, were blank, or were not secure.</p>
{/if}
{if password_expired}
  {passwd_form}
    New Password: <input type="password" name="newpass[1]" /><br/>
    New Password: <input type="password" name="newpass[2]" /><br/>
    <input type="submit" value="Change" />
  {/passwd_form}
{if:else}
  {passwd_form}
    Existing Password: <input type="password" name="oldpass" /><br/>
    New Password: <input type="password" name="newpass[1]" /><br/>
    New Password: <input type="password" name="newpass[2]" /><br/>
    <input type="submit" value="Change" />
  {/passwd_form}
{/if}
{/exp:passwd}
EOL;
	}
}
