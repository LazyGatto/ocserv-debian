#!/bin/sh
set -e

read -p "Enter Domain for this server: " DOMAIN
read -p "Enter CloudFlare API Key: " CF_API_KEY
read -p "Enter CloudFlare Email: " CF_EMAIL
read -p "Enter Camouflage Secret for this server: " SECRET
read -p "Enter listening port value for OCServ [443]: " PORT
PORT=${PORT:-443}

apt update && apt upgrade -y
apt-get install -y nftables libgnutls28-dev libev-dev autoconf make automake git \
	ipcalc-ng libpam0g-dev liblz4-dev libseccomp-dev \
	libreadline-dev libnl-route-3-dev libkrb5-dev libradcli-dev \
	libcurl4-gnutls-dev libcjose-dev libjansson-dev liboath-dev \
	libprotobuf-c-dev libtalloc-dev libhttp-parser-dev protobuf-c-compiler \
	gperf lcov libuid-wrapper libpam-wrapper libnss-wrapper \
	libsocket-wrapper gss-ntlmssp iputils-ping \
	gawk gnutls-bin iproute2 yajl-tools tcpdump \
    certbot python3-certbot-dns-cloudflare

wget https://gitlab.com/openconnect/ocserv/-/archive/1.3.0/ocserv-1.3.0.tar.gz
tar -xf ocserv-1.3.0.tar.gz
cd ocserv-1.3.0/
autoreconf -fvi
./configure && make && make install

useradd -M ocserv
usermod -L ocserv

cat > /etc/letsencrypt/certbot_cf.ini << EOF
dns_cloudflare_email = $CF_EMAIL
dns_cloudflare_api_key = $CF_API_KEY
EOF
chmod 600 /etc/letsencrypt/certbot_cf.ini

certbot certonly \
    --agree-tos \
    --email $CF_EMAIL \
    --dns-cloudflare \
    --dns-cloudflare-propagation-seconds 30 \
    --dns-cloudflare-credentials /etc/letsencrypt/certbot_cf.ini -d $DOMAIN -n

cat > /etc/letsencrypt/renewal-hooks/post/001-restart-ocserv.sh << EOF
#!/bin/bash
systemctl restart ocserv.service
EOF
chmod +x /etc/letsencrypt/renewal-hooks/post/001-restart-ocserv.sh

### Create support files for control ocserv
# Add, modify user

cat > /usr/local/bin/ocserv-add-user << EOF
#!/bin/sh
set -e

NEWUSR=\$1

if [ -z "\$1" ]
then
    echo "ERROR: Specify user please"
    exit
fi

if [ -z "\$2" ]
then
    PASSWD=\$(shuf -i 10000-99999 -n 1 | tr -d '\n')
else
    PASSWD=\$2
fi

echo -n "\$PASSWD\n\$PASSWD\n" | ocpasswd -c /etc/ocserv/ocpasswd \$NEWUSR

if grep -q \$NEWUSR /etc/ocserv/ocpasswd_plain; then
    echo "User EDITED"
    sed -i 's/^'"\$NEWUSR"'\s.*$/'"\$NEWUSR - \$PASSWD"'/g' /etc/ocserv/ocpasswd_plain
else
    echo "User ADDED"
    echo "\$NEWUSR - \$PASSWD" >> /etc/ocserv/ocpasswd_plain
fi
echo "Login: \$NEWUSR, Password: \$PASSWD"
EOF
chmod +x /usr/local/bin/ocserv-add-user

# Lock user
cat > /usr/local/bin/ocserv-lock-user << EOF
#!/bin/sh
set -e

NEWUSR=\$1

if [ -z "\$1" ]
then
    echo "Error: Specify username please"
    exit
fi

if grep -q \$NEWUSR /etc/ocserv/ocpasswd_plain; then
    ocpasswd -c /etc/ocserv/ocpasswd -l \$NEWUSR
    echo "User \$NEWUSR locked"
else
    echo "Sorry, User \$NEWUSR NOT FOUND, check your input"
fi
EOF
chmod +x /usr/local/bin/ocserv-lock-user

# Unlock user
cat > /usr/local/bin/ocserv-unlock-user << EOF
#!/bin/sh
set -e

NEWUSR=\$1

if [ -z "\$1" ]
then
    echo "Error: Specify username please"
    exit
fi

if grep -q \$NEWUSR /etc/ocserv/ocpasswd_plain; then
    ocpasswd -c /etc/ocserv/ocpasswd -u \$NEWUSR
    echo "User \$NEWUSR unlocked"
else
    echo "Sorry, User \$NEWUSR NOT FOUND, check your input"
fi
EOF
chmod +x /usr/local/bin/ocserv-unlock-user

# Delete user
cat > /usr/local/bin/ocserv-delete-user << EOF
#!/bin/sh
set -e

NEWUSR=\$1

if [ -z "\$1" ]
then
    echo "Error: Specify username please"
    exit
fi

if grep -q \$NEWUSR /etc/ocserv/ocpasswd_plain; then
    ocpasswd -c /etc/ocserv/ocpasswd -d \$NEWUSR
    grep -v \$NEWUSR /etc/ocserv/ocpasswd_plain > /tmp/ocpasswd_plain
    mv /tmp/ocpasswd_plain /etc/ocserv/ocpasswd_plain
    echo "User \$NEWUSR DELETED"
else
    echo "Sorry, User \$NEWUSR NOT FOUND, check your input"
fi
EOF
chmod +x /usr/local/bin/ocserv-delete-user

### Create config for ocserv

mkdir /etc/ocserv

cat > /etc/ocserv/ocserv.conf << EOF
auth = "plain[passwd=/etc/ocserv/ocpasswd]"
tcp-port = $PORT
udp-port = $PORT
run-as-user = ocserv
run-as-group = ocserv
socket-file = /var/run/ocserv-socket
server-cert = /etc/letsencrypt/live/$DOMAIN/fullchain.pem
server-key = /etc/letsencrypt/live/$DOMAIN/privkey.pem
isolate-workers = false
max-same-clients = 3
rate-limit-ms = 100
server-stats-reset-time = 604800
keepalive = 32400
dpd = 90
mobile-dpd = 1800
switch-to-tcp-timeout = 25
try-mtu-discovery = false
cert-user-oid = 0.9.2342.19200300.100.1.1
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1"
auth-timeout = 240
min-reauth-time = 300
max-ban-score = 80
ban-reset-time = 1200
ban-points-wrong-password = 10
ban-points-connection = 1
ban-points-kkdcp = 1
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-occtl = true
pid-file = /var/run/ocserv.pid
log-level = 2
device = vpns
predictable-ips = true
default-domain = $DOMAIN
ipv4-network = 172.16.0.0/24
tunnel-all-dns = true
dns = 1.1.1.1
ping-leases = false
route = default
config-per-user = /etc/ocserv/config-per-user/
cisco-client-compat = true
dtls-legacy = true
cisco-svc-client-compat = false
client-bypass-protocol = false
camouflage = true
camouflage_secret = "$SECRET"
camouflage_realm = "VestaCP Admin Panel"
# HTTP headers
included-http-headers = Strict-Transport-Security: max-age=31536000 ; includeSubDomains
included-http-headers = X-Frame-Options: deny
included-http-headers = X-Content-Type-Options: nosniff
included-http-headers = Content-Security-Policy: default-src 'none'
included-http-headers = X-Permitted-Cross-Domain-Policies: none
included-http-headers = Referrer-Policy: no-referrer
included-http-headers = Clear-Site-Data: "cache","cookies","storage"
included-http-headers = Cross-Origin-Embedder-Policy: require-corp
included-http-headers = Cross-Origin-Opener-Policy: same-origin
included-http-headers = Cross-Origin-Resource-Policy: same-origin
included-http-headers = X-XSS-Protection: 0
included-http-headers = Pragma: no-cache
included-http-headers = Cache-control: no-store, no-cache
EOF

# Create service file for ocserv

cat > /etc/systemd/system/ocserv.service << EOF
[Unit]
Description=OpenConnect SSL VPN server
Documentation=man:ocserv(8)
After=network-online.target

[Service]
PrivateTmp=true
PIDFile=/run/ocserv.pid
Type=simple
ExecStart=/usr/local/sbin/ocserv --foreground --pid-file /run/ocserv.pid --config /etc/ocserv/ocserv.conf
ExecReload=/bin/kill -HUP \$MAINPID

[Install]
WantedBy=multi-user.target
EOF

cat << EOF >> /etc/nftables.conf
table nat {
    chain postrouting {
        type nat hook postrouting priority srcnat;
        oif eth0 masquerade
    }
}
EOF

systemctl enable nftables.service
systemctl start nftables.service

cat << EOF >> /etc/sysctl.conf
net.ipv4.ip_forward = 1 
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

sysctl -p

systemctl daemon-reload
systemctl enable ocserv.service
systemctl start ocserv.service
systemctl status ocserv.service

cat << EOF >> /root/.ssh/authorized_keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINgOY0I2guCpdDUuQUHbKjHAQr9GW85bPXFyiYcZNdFe root@d2a-billing
EOF