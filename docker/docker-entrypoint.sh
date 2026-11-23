#!/bin/sh
# Entry point of the RackTables container image.
set -eu

# Behind a reverse proxy, RT_TRUSTED_PROXIES (space-separated addresses or
# CIDR blocks) makes Apache take the client address from X-Forwarded-For
# (login throttling, $client_ autotags), only for requests coming from these
# proxies, and HTTPS from X-Forwarded-Proto (HSTS, Secure cookie flag).
conf=/var/run/apache2/racktables-proxy.conf
if [ -n "${RT_TRUSTED_PROXIES:-}" ]; then
	case "$RT_TRUSTED_PROXIES" in
		*[!0-9A-Fa-f.:/\ ]*)
			echo "RT_TRUSTED_PROXIES: invalid value" >&2
			exit 1
			;;
	esac
	cat > "$conf" <<EOF
RemoteIPHeader X-Forwarded-For
RemoteIPTrustedProxy $RT_TRUSTED_PROXIES
SetEnvIf X-Forwarded-Proto "^https\$" HTTPS=on
EOF
else
	rm -f "$conf"
fi

# Create the database schema and the administrator account on first start.
php /usr/local/share/racktables/init-db.php

exec "$@"
