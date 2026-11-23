<?php

# This file is a part of RackTables, a datacenter and server room management
# framework. See accompanying file "COPYING" for the full copyright and
# licensing information.

/*
*
* This file is a library needed by all modules of RackTables (installer, upgrader)
* to make them able to find code and data.
*
*/

// required by exceptions.php
function isCLIMode()
{
	return ! isset ($_SERVER['REQUEST_METHOD']);
}

require_once 'exceptions.php';
require_once 'interface-lib.php';

// Always have default values for these options, so if a user didn't
// care to set, something would be working anyway.
$user_auth_src = 'database';
$require_local_account = TRUE;

$racktables_rootdir = realpath (dirname (__FILE__) . '/..'); // you can not override this
# Below are default values for several paths. The right way to change these
# is to add respective line(s) to secret.php, unless this is a "shared
# code, multiple instances" deploy, in which case the paths could be changed
# in the custom entry point wrapper (like own index.php)
if (! isset ($racktables_staticdir)) // the directory containing 'pix', 'js', 'css' dirs
	$racktables_staticdir = $racktables_rootdir;
if (! isset ($racktables_gwdir)) // the directory containing the 'telnet' and 'ssh' scripts
	$racktables_gwdir = realpath ($racktables_rootdir . '/../gateways');
if (! isset ($racktables_confdir)) // the directory containing secret.php (default is wwwroot/inc)
	$racktables_confdir = dirname (__FILE__);
if (! isset ($path_to_secret_php)) // you can overrride the path to secret.php separately from $racktables_confdir (legacy feature)
	$path_to_secret_php = $racktables_confdir . '/secret.php';
if (! isset ($racktables_plugins_dir)) // the directory where RT will load additional *.php files (like local.php) from
	$racktables_plugins_dir = realpath ($racktables_rootdir . '/../plugins');

// secret.php may be missing, generally it is OK
if (fileSearchExists ($path_to_secret_php))
{
	$found_secret_file = TRUE;
	require_once $path_to_secret_php;
}
else
	$found_secret_file = FALSE;

// determine local paths after loading of secret.php (maybe it has overrided racktables_plugins_dir)
if (! isset ($local_gwdir)) // the directory where RT will search gateway scripts if not found in $racktables_gwdir
	$local_gwdir = $racktables_plugins_dir . '/gateways';
if (! isset ($local_staticdir)) // the directory where RT will search static files (js/*, css/*, pix/*) if not found in $racktables_staticdir
	$local_staticdir = $racktables_plugins_dir;

// PHP 8.4 introduced Pdo\Mysql::ATTR_* and PHP 8.5 deprecated PDO::MYSQL_ATTR_*,
// the latter remain necessary for PHP 8.2 and 8.3.
function pdoMySQLAttr ($name)
{
	return constant (class_exists ('Pdo\\Mysql') ? "Pdo\\Mysql::ATTR_{$name}" : "PDO::MYSQL_ATTR_{$name}");
}

// Password hashes: Argon2id when available (bcrypt otherwise). Hashes made by
// earlier versions (unsalted SHA-1, 40 hex digits) are still accepted, then
// replaced on the next successful login.
function makePasswordHash ($password)
{
	return password_hash ($password, defined ('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT);
}

function isLegacyPasswordHash ($hash)
{
	return 1 === preg_match ('/^[0-9a-f]{40}$/D', $hash);
}

function verifyPasswordHash ($password, $hash)
{
	$hash = (string) $hash;
	if (isLegacyPasswordHash ($hash))
		return hash_equals ($hash, sha1 ($password));
	return $hash != '' && password_verify ($password, $hash);
}

function passwordHashNeedsRehash ($hash)
{
	return isLegacyPasswordHash ($hash) ||
		password_needs_rehash ($hash, defined ('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_DEFAULT);
}

function isValidPasswordHash ($hash)
{
	return isLegacyPasswordHash ($hash) || password_get_info ($hash)['algo'] !== NULL;
}

// HTTP basic authentication has no rate limit of its own: after too many
// failed logins from a client address within the window, refuse further
// attempts from it until the window has passed. The address, not the account,
// is throttled, so that nobody can lock out a legitimate user.
// Behind a reverse proxy, REMOTE_ADDR must be the client (mod_remoteip...).
define ('LOGIN_THROTTLE_MAX_FAILURES', 10);
define ('LOGIN_THROTTLE_WINDOW', 900); // seconds

function isLoginThrottled()
{
	global $dbxlink;
	if (isCLIMode() || ! isset ($_SERVER['REMOTE_ADDR']))
		return FALSE;
	try
	{
		$prepared = $dbxlink->prepare ('SELECT failures FROM LoginFailure WHERE ip = ? AND last_failure > NOW() - INTERVAL ? SECOND');
		$prepared->execute (array ($_SERVER['REMOTE_ADDR'], LOGIN_THROTTLE_WINDOW));
		return $prepared->fetchColumn() >= LOGIN_THROTTLE_MAX_FAILURES;
	}
	catch (PDOException $e)
	{
		return FALSE; // the table does not exist before the 0.22.1 upgrade
	}
}

function recordLoginFailure()
{
	global $dbxlink;
	if (isCLIMode() || ! isset ($_SERVER['REMOTE_ADDR']))
		return;
	try
	{
		$dbxlink->prepare
		(
			'INSERT INTO LoginFailure (ip, failures, last_failure) VALUES (?, 1, NOW()) ' .
			'ON DUPLICATE KEY UPDATE failures = IF(last_failure > NOW() - INTERVAL ? SECOND, failures + 1, 1), last_failure = NOW()'
		)->execute (array ($_SERVER['REMOTE_ADDR'], LOGIN_THROTTLE_WINDOW));
	}
	catch (PDOException $e)
	{
	}
}

// (re)connects to DB, stores PDO object in $dbxlink global var
function connectDB()
{
	global $dbxlink, $pdo_dsn, $db_username, $db_password, $pdo_bufsize, $pdo_ssl_key, $pdo_ssl_cert, $pdo_ssl_ca;
	$dbxlink = NULL;
	$drvoptions = array
	(
		PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
		// Cancel one specific SQL mode option that RackTables has been non-compliant
		// with, but which used to be off by default until MySQL 5.7. As soon as
		// respective SQL queries and table columns become compliant with those options
		// stop changing @@SQL_MODE but still keep SET NAMES in place.
		// RackTables requires the strict SQL mode, which is not enabled by default
		// in MariaDB <= 10.2.3.
		pdoMySQLAttr ('INIT_COMMAND') => 'SET NAMES "utf8", @@SQL_MODE = CONCAT("STRICT_ALL_TABLES,", REPLACE(@@SQL_MODE, "NO_ZERO_DATE", ""))',
	);
	if (isset ($pdo_bufsize))
		$drvoptions[pdoMySQLAttr ('MAX_BUFFER_SIZE')] = $pdo_bufsize;
	if (isset ($pdo_ssl_key))
		$drvoptions[pdoMySQLAttr ('SSL_KEY')] = $pdo_ssl_key;
	if (isset ($pdo_ssl_cert))
		$drvoptions[pdoMySQLAttr ('SSL_CERT')] = $pdo_ssl_cert;
	if (isset ($pdo_ssl_ca))
		$drvoptions[pdoMySQLAttr ('SSL_CA')] = $pdo_ssl_ca;
	try
	{
		$dbxlink = new PDO ($pdo_dsn, $db_username, $db_password, $drvoptions);
	}
	catch (PDOException $e)
	{
		throw new RackTablesError ("Database connection failed:\n\n" . $e->getMessage(), RackTablesError::INTERNAL);
	}
}

// tries to guess the existence of the file before the php's include using the same searching method.
// in addition to calling file_exists, searches the current file's directory if the path is not looks
// like neither absolute nor relative.
function fileSearchExists ($filename)
{
	if (! preg_match ('@^(\.+)?/@', $filename))
	{
		$this_file_dir = dirname (__FILE__);
		if (file_exists ($this_file_dir . '/' . $filename))
			return TRUE;
	}
	return file_exists ($filename);
}
