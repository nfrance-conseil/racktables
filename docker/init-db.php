<?php
# On the first start of the container, create the database schema and the
# administrator account (password from RT_ADMIN_PASSWORD_FILE or
# RT_ADMIN_PASSWORD). Later, only report whether an upgrade is pending: the
# upgrade is an administrator decision (back the database up first), it runs
# from index.php?module=upgrade.

chdir ('/var/www/racktables/wwwroot');
require_once 'inc/pre-init.php';
require_once 'inc/dictionary.php';
require_once 'inc/config.php';
require_once 'inc/install.php';

function initLog ($message)
{
	fwrite (STDERR, "racktables: {$message}\n");
}

function readSetting ($name)
{
	$file = getenv ($name . '_FILE');
	if ($file !== FALSE && $file !== '')
		return rtrim ((string) @file_get_contents ($file), "\r\n");
	$value = getenv ($name);
	return $value === FALSE ? '' : $value;
}

// The database container may still be starting.
for ($try = 1; ; $try++)
	try
	{
		connectDB();
		break;
	}
	catch (RackTablesError $e)
	{
		if ($try == 30)
		{
			initLog ('cannot connect to the database: ' . $e->getMessage());
			exit (1);
		}
		sleep (2);
	}

if ($dbxlink->query ("SHOW TABLES LIKE 'Config'")->fetchColumn() !== FALSE)
{
	$dbver = $dbxlink->query ("SELECT varvalue FROM Config WHERE varname = 'DB_VERSION'")->fetchColumn();
	if ($dbver != CODE_VERSION)
		initLog ("database version {$dbver}, code version " . CODE_VERSION . ': back the database up, then open index.php?module=upgrade');
	exit (0);
}

$password = readSetting ('RT_ADMIN_PASSWORD');
if (strlen ($password) < 12)
{
	initLog ('empty database: set RT_ADMIN_PASSWORD_FILE (12 characters or more) to create the administrator account');
	exit (1);
}
initLog ('empty database, creating the schema');
ob_start();
$ok = init_database_static();
$output = ob_get_clean();
if (! $ok || FALSE !== strpos ($output, 'failed'))
{
	initLog ('schema creation failed: ' . trim (strip_tags ($output)));
	exit (1);
}
$dbxlink->prepare
(
	"INSERT INTO UserAccount (user_id, user_name, user_password_hash, user_realname) " .
	"VALUES (1, 'admin', ?, 'RackTables Administrator')"
)->execute (array (makePasswordHash ($password)));
initLog ("schema created, log in as 'admin'");
