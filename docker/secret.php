<?php
# Configuration file of the container image: the settings come from the
# environment. A variable NAME_FILE takes precedence over NAME and holds the
# path of a file containing the value (Docker secrets).
#
#   RT_DB_HOST (db), RT_DB_PORT (3306), RT_DB_NAME (racktables),
#   RT_DB_USER (racktables), RT_DB_PASSWORD
#
# Other settings of secret.php (LDAP, SAML, $user_auth_src...) can be placed
# in /etc/racktables/secret.php, mounted into the container.

$rt_setting = function ($name, $default = '')
{
	$file = getenv ($name . '_FILE');
	if ($file !== FALSE && $file !== '')
	{
		if (FALSE === $value = @file_get_contents ($file))
			throw new RackTablesError ("cannot read the file named by {$name}_FILE", RackTablesError::MISCONFIGURED);
		return rtrim ($value, "\r\n");
	}
	$value = getenv ($name);
	return $value === FALSE || $value === '' ? $default : $value;
};

$pdo_dsn = sprintf
(
	'mysql:host=%s;port=%u;dbname=%s',
	$rt_setting ('RT_DB_HOST', 'db'),
	$rt_setting ('RT_DB_PORT', '3306'),
	$rt_setting ('RT_DB_NAME', 'racktables')
);
$db_username = $rt_setting ('RT_DB_USER', 'racktables');
$db_password = $rt_setting ('RT_DB_PASSWORD');
unset ($rt_setting);

if (is_readable ('/etc/racktables/secret.php'))
	require_once '/etc/racktables/secret.php';
