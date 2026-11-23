# syntax=docker/dockerfile:1
#
# RackTables container image: Apache httpd + mod_php on the Docker Official
# Image for PHP (Debian stable, rebuilt by Docker for every security update).
# The image runs as an unprivileged user, on port 8080, and works with a
# read-only root filesystem. See README.md, section "Docker deployment".

ARG PHP_IMAGE=php:8.5-apache-trixie
FROM ${PHP_IMAGE}

# PHP extensions: pdo_mysql (database), gd (rack images and thumbnails),
# bcmath (IPv6), ldap (LDAP authentication), snmp (SNMP discovery).
# The build dependencies are removed afterwards, only the runtime libraries
# the extensions link against are kept.
RUN set -eux; \
	savedAptMark="$(apt-mark showmanual)"; \
	apt-get update; \
	apt-get install -y --no-install-recommends \
		libfreetype-dev libjpeg62-turbo-dev libpng-dev libwebp-dev \
		libldap2-dev libsnmp-dev; \
	docker-php-ext-configure gd --with-freetype --with-jpeg --with-webp; \
	docker-php-ext-install -j"$(nproc)" pdo_mysql gd bcmath ldap snmp; \
	apt-mark auto '.*' > /dev/null; \
	[ -z "$savedAptMark" ] || apt-mark manual $savedAptMark; \
	find /usr/local/lib/php/extensions -type f -name '*.so' -exec ldd '{}' ';' \
		| awk '/=>/ { so = $(NF-1); if (index(so, "/usr/local/") == 1) { next }; gsub("^/(usr/)?", "", so); printf "*%s\n", so }' \
		| sort -u | xargs -r dpkg-query --search | cut -d: -f1 | sort -u | xargs -r apt-mark manual; \
	apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \
	apt-get upgrade -y; \
	rm -rf /var/lib/apt/lists/*; \
	php -m | grep -qE '^(pdo_mysql|gd|bcmath|ldap|snmp)$'

# PHP: production defaults plus RackTables settings.
RUN cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"
COPY docker/php.ini "$PHP_INI_DIR/conf.d/zz-racktables.ini"

# Apache: listen on an unprivileged port, serve only index.php and static files.
COPY docker/apache.conf /etc/apache2/sites-available/000-default.conf
RUN set -eux; \
	echo 'Listen 8080' > /etc/apache2/ports.conf; \
	a2enmod remoteip headers > /dev/null; \
	a2disconf other-vhosts-access-log serve-cgi-bin > /dev/null; \
	{ \
		echo 'ServerName localhost'; \
		echo 'ServerTokens Prod'; \
		echo 'ServerSignature Off'; \
		echo 'TraceEnable Off'; \
		echo 'IncludeOptional /var/run/apache2/racktables-*.conf'; \
	} > /etc/apache2/conf-available/zz-racktables.conf; \
	a2enconf zz-racktables > /dev/null; \
	chown www-data:www-data /var/run/apache2 /var/lock/apache2

# Application code, owned by root and read-only for the web server user.
COPY --chown=root:root wwwroot /var/www/racktables/wwwroot
COPY --chown=root:root gateways /var/www/racktables/gateways
COPY --chown=root:root plugins /var/www/racktables/plugins
COPY --chown=root:root docker/secret.php /var/www/racktables/wwwroot/inc/secret.php
COPY --chown=root:root --chmod=0755 docker/docker-entrypoint.sh /usr/local/bin/racktables-entrypoint
COPY --chown=root:root docker/init-db.php /usr/local/share/racktables/init-db.php
RUN set -eux; \
	chmod -R a=rX /var/www/racktables; \
	rm -rf /var/www/html

USER www-data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
	CMD curl -fsS -o /dev/null http://127.0.0.1:8080/pix/favicon.ico || exit 1
ENTRYPOINT ["racktables-entrypoint"]
CMD ["apache2-foreground"]
