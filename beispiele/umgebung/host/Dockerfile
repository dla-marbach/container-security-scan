# Testumgebung „Host“ (beispiele/erzeugen.sh, tests/test_docker.py): ein SLES-15-Server ohne Docker, Dienste
# direkt aus den Paketen der Distribution, ohne systemd gestartet (start.sh). Bauen im Verzeichnis darüber:
#   docker build -t css-beispiel-host -f host/Dockerfile beispiele/umgebung
# - nginx: öffentliche Website (80/443) mit eingebettetem jQuery, /app/ an Apache; Statusseite ohne Beschränkung,
#   Partner-Schnittstelle mit TLS 1.0 (8443), Intranet-Website mit Verzeichnisliste
# - Apache (nur 127.0.0.1:8080): PHP-Anwendung samt vendor/ über php-fpm (127.0.0.1:9000); server-status
#   „nur localhost“ (SLES-Standard), über nginx aber erreichbar
# - Python-Webserver an 0.0.0.0:8000, den firewalld sperrt
# Proxy mit eigener Zertifizierungsstelle für den Build: --secret id=ca,src=<Datei> (optional)
FROM registry.suse.com/bci/bci-base:15.7
RUN --mount=type=secret,id=ca,required=false \
    if [ -s /run/secrets/ca ]; then cp /run/secrets/ca /etc/pki/trust/anchors/build-ca.pem && update-ca-certificates; fi \
 && zypper -n --quiet in --no-recommends nginx apache2 apache2-prefork php8 php8-fpm python3 iproute2 procps \
        firewalld dbus-1 openssl util-linux hostname >/dev/null \
 && zypper -n --quiet clean -a \
 && rm -f /etc/pki/trust/anchors/build-ca.pem && update-ca-certificates
COPY host/nginx-www.conf /etc/nginx/vhosts.d/www.conf
COPY host/apache-app.conf /etc/apache2/vhosts.d/app.conf
COPY host/start.sh /usr/local/sbin/start.sh
COPY php/ /srv/www/app/
COPY php/public/js/jquery-1.12.4.min.js /srv/www/htdocs/js/
RUN set -e; mkdir -p /etc/nginx/ssl /srv/www/intranet/dokumente; \
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj /CN=www.example.org \
        -keyout /etc/nginx/ssl/www.key -out /etc/nginx/ssl/www.crt 2>/dev/null; \
    sed -i 's/^Listen 80$/Listen 127.0.0.1:8080/' /etc/apache2/listen.conf; \
    sed -i -e 's/^APACHE_MODULES="\(.*\)"/APACHE_MODULES="\1 proxy proxy_fcgi status"/' -e 's/ php8\b//' \
        /etc/sysconfig/apache2; \
    echo "Protokoll" > /srv/www/intranet/dokumente/protokoll.txt; chmod 755 /usr/local/sbin/start.sh
CMD ["/usr/local/sbin/start.sh"]
