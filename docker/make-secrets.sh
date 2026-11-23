#!/bin/sh
# Generate the random passwords used by compose.yaml, unless they exist.
set -eu
cd "$(dirname "$0")/.."
mkdir -p secrets
chmod 0700 secrets
for name in db_password db_root_password admin_password; do
	file="secrets/$name.txt"
	if [ ! -e "$file" ]; then
		(umask 0222; head -c 24 /dev/urandom | base64 | tr -d '/+=\n' > "$file")
		echo "created $file"
	fi
done
# The files are bind-mounted into the containers, where the web server user
# must read them; the 0700 directory keeps them private on the host.
chmod 0444 secrets/*.txt
echo "administrator password: $(cat secrets/admin_password.txt)"
