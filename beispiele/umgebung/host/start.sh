#!/bin/sh
# Dienste der Testumgebung starten (im Container ohne systemd); /run/bereit, wenn alle laufen
set -e
mkdir -p /run/dbus
dbus-daemon --system --fork
firewalld --nofork --nopid >/var/log/firewalld.log 2>&1 &
for _ in $(seq 60); do firewall-cmd --state >/dev/null 2>&1 && break; sleep 1; done
firewall-cmd --zone=public --add-service=http --add-service=https >/dev/null
firewall-cmd --zone=public --add-port=8443/tcp >/dev/null
/usr/sbin/php-fpm --nodaemonize --fpm-config /etc/php8/fpm/php-fpm.conf &
/usr/sbin/start_apache2 -DFOREGROUND -k start &
nginx
cd /srv/www/intranet && python3 -m http.server 8000 >/dev/null 2>&1 &
touch /run/bereit
exec sleep infinity
